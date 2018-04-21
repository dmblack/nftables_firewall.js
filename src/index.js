const sysClassNetInterfaces = '/sys/class/net/';
const fs = require('fs');
const nfq = require('nfqueue');
const IPv4 = require('pcap/decode/ipv4');
const pcap = require('pcap');
const { exec } = require('child_process');
const nfpacket = require('./nfpacket')({ nfq: nfq, pcap: pcap })

const nft = require('./nftables')({ exec: exec });

// These are the NFQUEUE result handler options.
const NF_REJECT = 0;
const NF_ACCEPT = 1; // Accept packet (but no longer seen / disowned by conntrack)
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

let rules = require('./config/rules.json').rules;
let systemInterfaces = require('./config/interfaces.json').interfaces;

let configWatch = fs.watch('./src/config', checkConfig);

function checkConfig (err, filename) {
  setTimeout(() => {
    console.log(filename);
    console.log(err)
    switch (filename) {
      case 'rules.json':
        console.log('Rules Configuration Changed - Reloding..')
        fs.readFile('./src/config/rules.json', 'utf8', (err, data) => {
          if (err) throw err;
          let newRules = JSON.parse(data);
          rules = newRules.rules;
        });
        break;
      case 'interfaces.json':
        console.log('Interfaces Configuration Changed - Reloding..')
        fs.readFile('./src/config/interfaces.json', 'utf8', (err, data) => {
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
let interfaces = []

// Sets base rules, with default to 'drop', but allows established and related connections.
function insertFinalCounters () {
  return Promise.all([
    nft.add('rule ip filter input counter'),
    nft.add('rule ip filter output counter'),
  ])
}

function insertInterfaceRules (interface) {
  return Promise.all([
    nft.add('rule ip filter input iif ' + interface.name + ' ct state new counter nftrace set 1 queue num ' + interface.number),
    nft.add('rule ip filter output oif ' + interface.name + ' ct state new counter nftrace set 1 queue num 100' + interface.number)
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
function runPromiseInSequense(arr) {
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

  return runPromiseInSequense(interfacePromises)
};

function determineVerdict (interface, packet, direction) {
  let thisVerdict = NF_REJECT;

  // Check we even handle this protocol
  if (rules[direction][packet.protocol.toString()]) {
    // Check if the global (blanket) rule applies
    if (rules[direction][packet.protocol.toString()].global.allowed) {
      // Trigger the callback, if it exists..
      if (rules[direction][packet.protocol.toString()].global.acceptCallback) {
        eval(rules[direction][packet.protocol.toString()].global.acceptCallback)(packet);
      }
      // Check if the global setting has any specific ports
      if (rules[direction][packet.protocol.toString()].global.ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[direction][packet.protocol.toString()].global.ports[packet.payload.dport]) {
          thisVerdict = NF_ACCEPT;
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[direction][packet.protocol.toString()].global.ports[packet.payload.dport].acceptCallback) {
            eval(rules[direction][packet.protocol.toString()].global.ports[packet.payload.dport].acceptCallback)(packet);
          }
          return thisVerdict;
        }
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
      } else {
        thisVerdict = NF_ACCEPT;
        return thisVerdict;
      }
      // Else, as if globally accepted we don't need to traverse other zones.
    }
    // Check if the protocol is zone allowed.
    if (rules[direction][packet.protocol.toString()][interface.zone].allowed) {
      // Trigger the protocol zone callback, if it exists.
      if (rules[direction][packet.protocol.toString()][interface.zone].acceptCallback) {
        eval(rules[direction][packet.protocol.toString()][interface.zone].acceptCallback)(packet);
      }
      // Check if the protocol's zone setting has any specific ports
      if (rules[direction][packet.protocol.toString()][interface.zone].ports) {
        // Check, if there are ports, if the port is allowed.
        if (rules[direction][packet.protocol.toString()][interface.zone].ports[packet.payload.dport]) {
          thisVerdict = NF_ACCEPT;
          // Finally - if the port is allowed, check if there's a callback to trigger.
          if (rules[direction][packet.protocol.toString()][interface.zone].ports[packet.payload.dport].acceptCallback) {
            eval(rules[direction][packet.protocol.toString()][interface.zone].ports[packet.payload.dport].acceptCallback)(packet);
          }
        }
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
      } else {
        thisVerdict = NF_ACCEPT;
      }
    }
  }

  return thisVerdict;
}

function updateOutput () {
  process.stdout.write('\x1Bc');
  process.stdout.write('Connections - Accepted: ' + packetsAccepted + ' (I: ' + packetsAcceptedIn + ' O: ' + packetsAcceptedOut + ') - Rejected: ' + packetsRejected + ' (I: ' + packetsRejectedIn + ' O: ' + packetsRejectedOut + ')\r');
}

function bindQueueHandlers () {
  interfaces.forEach(interface => {
    interface.queueIn = nfq.createQueueHandler(parseInt(interface.number), buffer, (nfpacket) => {
      let packet = new IPv4().decode(nfpacket.payload, 0);
      let thisVerdict = determineVerdict(interface, packet, 'incoming');

      if (thisVerdict === NF_REJECT) {
        packetsRejected++;
        packetsRejectedIn++;
        nfpacket.setVerdict(NF_REQUEUE, 666);
      } else {
        packetsAccepted++;
        packetsAcceptedIn++;
        nfpacket.setVerdict(NF_REQUEUE, 999);
      }
    });

    interface.queueOut = nfq.createQueueHandler(parseInt('100' + interface.number), buffer, (nfpacket) => {
      let packet = new IPv4().decode(nfpacket.payload, 0);
      let thisVerdict = determineVerdict(interface, packet, 'outgoing');

      // Allow us to set a META MARK for requeue and reject.
      if (thisVerdict === NF_REJECT) {
        packetsRejected++;
        packetsRejectedOut++;
        // Outgoing packets set META MARK 777 - allows use of REJECT
        //    icmp-admin-prohibited (so connections fail immediately, instead
        //    of timing out over a period of time... which is annoying locally)
        nfpacket.setVerdict(NF_REQUEUE, 777);
      } else {
        packetsAccepted++;
        packetsAcceptedOut++;
        nfpacket.setVerdict(NF_REQUEUE, 999);
      }
    });
  })
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

const outputInterval = setInterval(updateOutput, 2500);
