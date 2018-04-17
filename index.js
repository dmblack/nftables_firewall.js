const sysClassNetInterfaces = '/sys/class/net/';
const fs = require('fs');
const nfq = require('nfqueue');
const IPv4 = require('pcap/decode/ipv4');
let rules = require('./rules.json').rules;
// const rules = require('./rules.json').rules;
const systemInterfaces = require('./interfaces.json').interfaces;
const { exec } = require('child_process');

const nft = require('./src/nftables')({ exec: exec });

let ruleWatch = fs.watch('./rules.json', 'utf8', () => { setTimeout(loadRules, 500) });

function loadRules (err, filename) {
  console.log('Detected ' + filename + ' change. Ingesting.');
  fs.readFile('./rules.json', 'utf8', (err, data) => {
    if (err) throw err;
    let newRules = JSON.parse(data);
    rules = newRules.rules;
  });
}

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

// Some counters for connection analysis (Used for stdio)
let packetsAccepted = 0;
let packetsAcceptedIn = 0;
let packetsAcceptedOut = 0;
let packetsRejected = 0;
let packetsRejectedIn = 0;
let packetsRejectedOut = 0;

// An array to store our interfaces.
let interfaces = []

function execute (command) {
  return new Promise(function (resolve, reject) {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        reject(err)
      } else {
        resolve(stdout);
      }
    });
  });
}

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

function setupInterfaces () {
  let interfacePromises = [];
  getInterfaces(sysClassNetInterfaces).forEach(interface => {
    let newInterface = { name: interface, number: interfaces.length + 1, zone: systemInterfaces[interface].zone };
    interfacePromises.push(insertInterfaceRules(newInterface))
    interfaces.push(newInterface);
  });
  return Promise.all(interfacePromises);
};

function determineVerdict (interface, packet, direction) {
  let thisVerdict = NF_REJECT;

  // Check we even handle this protocol
  if (rules[direction][packet.protocol.toString()]) {
    // Check if the global (blanket) rule applies
    if (rules[direction][packet.protocol.toString()].global.enabled) {
      if (rules[direction][packet.protocol.toString()].global.ports) {
        if (rules[direction][packet.protocol.toString()].global.ports[packet.payload.dport]) {
          thisVerdict = NF_ACCEPT;
          return thisVerdict;
        }
      } else {
        // The global default is enabled, yet there are no ports.. which likely
        //    Means this is a port-less protocol.
        thisVerdict = NF_ACCEPT;
        return thisVerdict;
      }
      // Else, as if globally accepted we don't need to traverse other zones.
    }
    if (rules[direction][packet.protocol.toString()][interface.zone].enabled) {
      if (rules[direction][packet.protocol.toString()][interface.zone].ports) {
        if (rules[direction][packet.protocol.toString()][interface.zone].ports[packet.payload.dport]) {
          thisVerdict = NF_ACCEPT;
        }
      } else {
        thisVerdict = NF_ACCEPT;
      }
    }
  }

  return thisVerdict;
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

      process.stdout.write('Connections - Accepted: ' + packetsAccepted + ' (I: ' + packetsAcceptedIn + ' O: ' + packetsAcceptedOut + ') - Rejected: ' + packetsRejected + ' (I: ' + packetsRejectedIn + ' O: ' + packetsRejectedOut + ')\r');
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

      process.stdout.write('Connections - Accepted: ' + packetsAccepted + ' (I: ' + packetsAcceptedIn + ' O: ' + packetsAcceptedOut + ') - Rejected: ' + packetsRejected + ' (I: ' + packetsRejectedIn + ' O: ' + packetsRejectedOut + ')\r');
    });
  })
}

nft.flush().then(
  (resolved) => nft.inject('./base.rules'),
  (reject) => console.log('failed to flush rules')
).then(
  (resolved) => setupInterfaces(),
  (reject) => console.log('failed to inject base rules ')
).then(
  (resolved) => bindQueueHandlers(),
  (reject) => console.log('Failed to setup interfaces')
).then(
  (resolved) => insertFinalCounters(),
  (reject) => console.log('Failed to bind queue handlers')
);
