const sysClassNetInterfaces = '/sys/class/net/';
const fs = require('fs');
const nfq = require('nfqueue');
const IPv4 = require('pcap/decode/ipv4');
const pcap = require('pcap');
const { exec } = require('child_process');
const nft = require('./nftables')({ exec: exec });
const netFilterPacket = require('./nfpacket')({ nfq: nfq, pcapIPv4: IPv4 });
const actions = require('./actions')({ fs: fs });

// These are the NFQUEUE result handler options.
const NF_DROP = 0;  // Drop the packet (There is no response or closure)
const NF_ACCEPT = 1;  // Accept packet (but no longer seen / disowned by conntrack)
const NF_REQUEUE = 4; // Requeue packet (Which we then use a mark to determine the action)

// Protocol Numbers can be found here, however; libpcap has limited support..
//   https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const PC_ICMP = 1;
const PC_IGMP = 2;
const PC_TCP = 6;
const PC_UDP = 17;

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

function determineVerdict (interface, packet, direction) {
  let verdict = {
    policy: NF_DROP,
  };

  // Check if the source port is as our otherwise accepted outgoing destination port, but only on incoming connections
  // (Basically; established / releated comms)
  //    Required since 'logging' change complexity - but REQUIRES refactor
  // if (direction === 'incoming' && typeof rules['outgoing'][packet.payloadDecoded.protocol.toString()][interface.zone].ports !== 'undefined') {
  //   if (typeof rules['outgoing'][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.sport] !== 'undefined') {
  //     console.log('Incoming packet which has a sourceport listed in destination port lists');
  //     if (rules['outgoing'][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.sport].policy && rules['outgoing'][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.sport].policy === 'allow') {
  //       console.log("Possible Related Connection: %s", JSON.stringify(packet));
  //       verdict.policy = NF_ACCEPT;

  //       return verdict;
  //     }
  //   }
  // }

  // Check we even handle this protocol
  if (rules[direction][packet.payloadDecoded.protocol.toString()]) {
    // Check if the global (blanket) rule applies
    if (rules[direction][packet.payloadDecoded.protocol.toString()].global.policy && rules[direction][packet.payloadDecoded.protocol.toString()].global.policy === 'allow') {
      // Trigger the callback, if it exists..
      if (rules[direction][packet.payloadDecoded.protocol.toString()].global.action) {
        handleActions(rules[direction][packet.payloadDecoded.protocol.toString()].global.action, packet);
        if (rules[direction][packet.payloadDecoded.protocol.toString()].global.action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the global setting has any specific ports
      if (rules[direction][packet.payloadDecoded.protocol.toString()].global.ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport]) {
          // Check if the policy is allow
          if (rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport].policy && rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport].policy === 'allow') {
            // Set to accept packet.
            verdict.policy = NF_ACCEPT;
          }
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport].action) {
            handleActions(rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport].action, packet);
            if (rules[direction][packet.payloadDecoded.protocol.toString()].global.ports[packet.payloadDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
          // Do not further traverse ruleset, or this function ; wasted cycles.
          return verdict;
        }
        // The global default is enabled, yet there is no ports key..
        //    (Likely) means this is a port-less protocol, or a blanket 'allow' rule is in place.
      } else {
        verdict.policy = NF_ACCEPT;
        return verdict;
      }
      // Else, as if globally accepted we don't need to traverse other zones.
    }
    // Check if the protocol is zone allowed.
    if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].policy && rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].policy === 'allow') {
      // Trigger the protocol zone callback, if it exists.
      if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].action) {
        handleActions(rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].action, packet);
        if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the protocol's zone setting has any specific ports
      if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.dport].policy && rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.dport].policy === 'allow') {
          verdict.policy = NF_ACCEPT;
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.dport].action) {
            handleActions(rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.dport].action, packet);
            if (rules[direction][packet.payloadDecoded.protocol.toString()][interface.zone].ports[packet.payloadDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
        }
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
      } else {
        verdict.policy = NF_ACCEPT;
      }
    }
  }

  return verdict;
}

function handlePacket (interface, packet) {
  let verdict = {
    policy: NF_DROP,
    mark: 0
  };

  // Check we even handle this protocol
  if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()]) {
    // Check if the global (blanket) rule applies
    if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.policy && rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.policy === 'allow') {
      // Trigger the callback, if it exists..
      if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.action) {
        handleActions(rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.action, packet);
        if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the global setting has any specific ports
      if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport]) {
          // Check if the policy is allow
          if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport].policy && rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport].policy === 'allow') {
            // Set to accept packet.
            verdict.policy = NF_ACCEPT;
          }
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport].action) {
            handleActions(rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport].action, packet);
            if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()].global.ports[packet.state.nfpacketDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
          // Do not further traverse ruleset, or this function ; wasted cycles.
          packet.state.nfpacket.setVerdict(verdict.policy, verdict.mark);
        }
        // The global default is enabled, yet there is no ports key..
        //    (Likely) means this is a port-less protocol, or a blanket 'allow' rule is in place.
      } else {
        verdict.policy = NF_ACCEPT;
        packet.state.nfpacket.setVerdict(verdict.policy, verdict.mark);
      }
      // Else, as if globally accepted we don't need to traverse other zones.
    }
    // Check if the protocol is zone allowed.
    if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].policy && rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].policy === 'allow') {
      // Trigger the protocol zone callback, if it exists.
      if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].action) {
        handleActions(rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].action, packet);
        if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].action === 'log') {
          verdict.mark = 9999;
        }
      }
      // Check if the protocol's zone setting has any specific ports
      if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport] && rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport].policy && rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport].policy === 'allow') {
          verdict.policy = NF_ACCEPT;
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport].action) {
            handleActions(rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport].action, packet);
            if (rules[packet.getDirection()][packet.state.nfpacketDecoded.protocol.toString()][packet.getInterface().zone].ports[packet.state.nfpacketDecoded.payload.dport].action === 'log') {
              verdict.mark = 9999;
            }
          }
        }
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
      } else {
        verdict.policy = NF_ACCEPT;
      }
    }
  }

  packet.state.nfpacket.setVerdict(verdict.policy, verdict.mark);
}

function updateOutput () {
  process.stdout.write('\x1Bc');
  process.stdout.write('Connections - Accepted: ' + packetsAccepted + ' (I: ' + packetsAcceptedIn + ' O: ' + packetsAcceptedOut + ') - Rejected: ' + packetsRejected + ' (I: ' + packetsRejectedIn + ' O: ' + packetsRejectedOut + ')\r');
}

function bindQueueHandlers () {
  interfaces.forEach(interface => {
    interface.queueIn = nfq.createQueueHandler(parseInt(interface.number), buffer, (nfpacket) => {
      let thisPacket = netFilterPacket(nfpacket);
      thisPacket.setDirection('incoming');
      thisPacket.setInterface(interface);

      thisPacket.encoding.decode();

      handlePacket(interface, thisPacket);
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
      thisPacket.setDirection('outgoing');
      thisPacket.setInterface(interface);

      thisPacket.encoding.decode();

      handlePacket(interface, thisPacket);
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
