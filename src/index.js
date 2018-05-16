const sysClassNetInterfaces = '/sys/class/net/';
const fs = require('fs');
const nfq = require('nfqueue');
const IPv4 = require('pcap/decode/ipv4');
const pcap = require('pcap');
const { exec } = require('child_process');
const nft = require('./nftables')({ exec: exec });
const netFilterPacket = require('./nfpacket')({ nfq: nfq, pcapIPv4: IPv4 });
const actions = require('./actions')({ fs: fs });

// The buffer size we will use binding to nfqueues.
const buffer = 131070;

process.stdout.write('\x1Bc');

let rules = require('./../config/rules.json').rules;
let systemInterfaces = require('./../config/interfaces.json').interfaces;

let configWatch = fs.watch('./config', checkConfig);

function checkConfig (err, filename) {
  setTimeout(() => {
    switch (filename) {
      case 'rules.json':
        console.log('Rules Configuration Changed - Reloding..')
        fs.readFile('./config/rules.json', 'utf8', (err, data) => {
          if (err) throw err;
          let newRules = JSON.parse(data);
          rules = newRules.rules;
        });
        break;
      case 'interfaces.json':
        console.log('Interfaces Configuration Changed - Reloding..')
        fs.readFile('./config/interfaces.json', 'utf8', (err, data) => {
          if (err) throw err;
          let newInterfaces = JSON.parse(data);
          systemInterfaces = newInterfaces.interfaces;
        });
        break;
    }
  }, 500)
}

// Some counters for connection analysis (Used for stdio)
let packetsAccepted = 0;
let packetsAcceptedIn = 0;
let packetsAcceptedOut = 0;
let packetsRejected = 0;
let packetsRejectedIn = 0;
let packetsRejectedOut = 0;

// An array to store our interfaces.
let interfaces = [];

// Sets base rules, with default to 'drop', but allows established and related connections.
function insertFinalCounters () {
  return Promise.all([
    nft.add('rule ip filter input ct state { established, related } counter accept'),
    nft.add('rule ip filter input counter'),
    nft.add('rule ip filter output ct state { established, related } counter accept'),
    nft.add('rule ip filter output counter'),
  ])
}

function insertInterfaceRules (interface) {
  return Promise.all([
    nft.add('rule ip filter input iif ' + interface.name + ' counter nftrace set 1 queue num ' + interface.number),
    // nft.add('rule ip filter input iif ' + interface.name + ' meta mark 9999 counter nftrace set 1 queue num 200' + interface.number),
    nft.add('rule ip filter output oif ' + interface.name + ' counter nftrace set 1 queue num 100' + interface.number),
    // nft.add('rule ip filter output oif ' + interface.name + ' meta mark 9999 counter nftrace set 1 queue num 210' + interface.number)
  ]);
}

function getInterfaces (path) {
  const interfaces = fs.readdirSync(path);

  return interfaces instanceof (Array)
    ? interfaces
    : [];
}

/**
 * Runs promises from promise array in chained manner
 *
 * @param {array} arr - promise arr
 * @return {Object} promise object
 */
function runPromiseArrayInSequence (arr) {
  return arr.reduce((promiseChain, currentPromise) => {
    return promiseChain.then((chainedResult) => {
      return currentPromise(chainedResult)
        .then((res) => res)
    })
  }, Promise.resolve());
}

function setupInterfaces () {
  let interfacePromises = [];

  getInterfaces(sysClassNetInterfaces).forEach(interface => {
    let zone = 'untrusted'
    if (systemInterfaces[interface] && systemInterfaces[interface].zone) {
      zone = systemInterfaces[interface].zone || 'untrusted';
    }
    let newInterface = { name: interface, number: interfaces.length + 1, zone };
    interfacePromises.push(() => insertInterfaceRules(newInterface))
    interfaces.push(newInterface);
  });

  return runPromiseArrayInSequence(interfacePromises)
};

function handleActions (action, packet) {
  switch (action) {
    case 'log':
      actions.log(JSON.stringify(packet));
      break;
    default:
      break;
  }
}

function handlePacket (packet) {
  let verdict = {
    policy: packet.enums.netfilterVerdict.NF_DROP,
    mark: 0
  };

  // Check we even handle this protocol
  if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()]) {
    // Check if the global (blanket) rule applies
    if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.policy && rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.policy === 'allow') {
      // Trigger the callback, if it exists..
      if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.action) {
        handleActions(rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.action, packet);
        if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the global setting has any specific ports
      if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport]) {
          // Check if the policy is allow
          if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport].policy && rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport].policy === 'allow') {
            // Set to accept packet.
            verdict.policy = packet.enums.netfilterVerdict.NF_ACCEPT;
          }
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport].action) {
            handleActions(rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport].action, packet);
            if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()].global.ports[packet.nfpacketDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
          // Do not further traverse ruleset, or this function ; wasted cycles.
          packet.nfpacket.setVerdict(verdict.policy, verdict.mark);
        }
        // The global default is enabled, yet there is no ports key..
        //    (Likely) means this is a port-less protocol, or a blanket 'allow' rule is in place.
      } else {
        verdict.policy = packet.enums.netfilterVerdict.NF_ACCEPT;
        packet.nfpacket.setVerdict(verdict.policy, verdict.mark);
      }
      // Else, as if globally accepted we don't need to traverse other zones.
    }
    // Check if the protocol is zone allowed.
    if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].policy && rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].policy === 'allow') {
      // Trigger the protocol zone callback, if it exists.
      if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].action) {
        handleActions(rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].action, packet);
        if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the protocol's zone setting has any specific ports
      if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport] && rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport].policy && rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport].policy === 'allow') {
          verdict.policy = packet.enums.netfilterVerdict.NF_ACCEPT;
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport].action) {
            handleActions(rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport].action, packet);
            if (rules[packet.direction][packet.nfpacketDecoded.protocol.toString()][packet.interface.zone].ports[packet.nfpacketDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
        }
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
      } else {
        verdict.policy = packet.enums.netfilterVerdict.NF_ACCEPT;
      }
    }
  }

  packet.nfpacket.setVerdict(verdict.policy, verdict.mark);
}

function updateOutput () {
  process.stdout.write('\x1Bc');
  process.stdout.write('Connections - Accepted: ' + packetsAccepted + ' (I: ' + packetsAcceptedIn + ' O: ' + packetsAcceptedOut + ') - Rejected: ' + packetsRejected + ' (I: ' + packetsRejectedIn + ' O: ' + packetsRejectedOut + ')\r');
}

function bindQueueHandlers () {
  interfaces.forEach(interface => {
    interface.queueIn = nfq.createQueueHandler(parseInt(interface.number), buffer, (nfpacket) => {
      let thisPacket = netFilterPacket(nfpacket);
      thisPacket.direction = 'incoming';
      thisPacket.interface = interface;
      
      thisPacket.encoding.decode();

      handlePacket(thisPacket);
    });

    interface.queueInLog = nfq.createQueueHandler(parseInt('200' + interface.number), buffer, (nfpacket) => {
      let decoded = new IPv4().decode(nfpacket.payload, 0);
      let stringified = nfpacket.payload.toString();
      let clonedPacket = Object.assign({}, nfpacket, { payloadDecoded: decoded, payloadStringified: stringified });

      handleActions('log', packet);

      nfpacket.setVerdict(thisVerdict.policy, 9999);
    });

    interface.queueOut = nfq.createQueueHandler(parseInt('100' + interface.number), buffer, (nfpacket) => {
      let thisPacket = netFilterPacket(nfpacket);
      thisPacket.direction = 'outgoing';
      thisPacket.interface = interface;
      
      thisPacket.encoding.decode();

      handlePacket(thisPacket);
    });

    interfaceLoggerQueueOut = nfq.createQueueHandler(parseInt('210' + interface.number), buffer, (nfpacket) => {
      let decoded = new IPv4().decode(nfpacket.payload, 0);
      let stringified = nfpacket.payload.toString();
      let clonedPacket = Object.assign({}, nfpacket, { payloadDecoded: decoded, payloadStringified: stringified });

      handleActions('log', packet);

      nfpacket.setVerdict(thisVerdict.policy, 9999);
    });

  });
}

console.log('Flushing rules...');
nft.flush().then(
  (resolved) => {
    console.log('Injecting NFTables base ruleset...');
    nft.inject('./src/config/rules-base.nft')
  },
  (reject) => console.log('Failed to flush rules: ' + reject)
).then(
  (resolved) => {
    console.log('Configuring interfaces...');
    setupInterfaces();
  },
  (reject) => console.log('Failed to inject base rules: ' + reject)
).then(
  (resolved) => {
    console.log('Binding NFQueue handlers...');
    bindQueueHandlers();
  },
  (reject) => console.log('Failed to setup interfaces: ' + reject)
).then(
  (resolved) => {
    console.log('Inserting final (counter) rules...');
    setTimeout(insertFinalCounters, 2000);
  },
  (reject) => console.log('Failed to bind queue handlers: ' + reject)
).catch(
  (err) => console.log('Failed to insert final counters: ' + err)
);

const outputInterval = setInterval(updateOutput, 5000);
