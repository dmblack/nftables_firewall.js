const sysClassNetInterfaces = '/sys/class/net/';
const fs = require('fs');
const nfq = require('nfqueue');
const IPv4 = require('pcap/decode/ipv4');
const rules = require('./rules.json').rules;
const { trusted, untrusted } = require('./interfaces.json').interfaces;
const { exec } = require('child_process');

const NF_ACCEPT = 1; // Accept packet (but no longer seen / disowned by conntrack)
const NF_REJECT = 4; // Requeue packet (Which we then use a mark to determine the action)

const interfaces = []

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

// Flushes all rules - entirely blank.
function flushRules () {
  console.log('flush rules');
  return execute('nft flush ruleset');
}

// Sets locked down (besides lo) rules. No packets accepted at all.
function lockRules () {
  return execute('nft -f ./locked.rules');
}

// Sets base rules, with default to 'drop', but allows established and related connections.
function baseRules () {
  console.log('base rules');
  return execute('nft -f ./base.rules');
}

// Sets base rules, with default to 'drop', but allows established and related connections.
function insertFinalCounters () {
  console.log('final counters');
  return Promise.all([
    execute('nft add rule ip filter input counter'),
    execute('nft add rule ip filter output counter'),
  ])
}

const checkInterfaceRules = (interface) => {

}

function insertInterfaceRules (interface) {
  return Promise.all(
    [
      execute('nft add rule ip filter input iif ' + interface.name + ' ct state new counter nftrace set 1 queue num ' + interface.number),
      execute('nft add rule ip filter output oif ' + interface.name + ' ct state new counter nftrace set 1 queue num 100' + interface.number)
    ]
  )
}

const determineVerdict = (rules, port) => {
  let trusted = interfaces_trusted.includes(interface);

  if (trusted) {
    return
  } else {

  }
}

const setVerdict = (packet, verdict) => packet.setVerdict(verdict);

function getInterfaces (path) {
  const interfaces = fs.readdirSync(path);

  return interfaces instanceof (Array)
    ? interfaces
    : [];
}

function setupInterfaces () {
  return new Promise(function (resolve, reject) {
    getInterfaces(sysClassNetInterfaces).forEach(interface => {
      let isTrusted = trusted.includes(interface);
      let newInterface = { name: interface, number: interfaces.length + 1, trusted: isTrusted };
      insertInterfaceRules(newInterface);
      interfaces.push(newInterface);
      return resolve(true);
    });
  });
}

function bindQueueHandlers () {
  interfaces.forEach(interface => {
    console.log('Binding for interface: ' + interface);
    interface.queueIn = nfq.createQueueHandler(interface.number, 65535, (nfpacket) => {
      let packet = new IPv4().decode(nfpacket.payload, 0);
      let thisVerdict = NF_REJECT;

      switch (packet.protocol) {
        case 6:
          console.log('tcp')
          if (rules.incoming.global_tcp.includes(packet.payload.dport.toString()) === true) {
            console.log('accept global');
            thisVerdict = NF_ACCEPT
          } else {
            if (interface.trusted) {
              if (rules.incoming.trusted_tcp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept trusted');
                thisVerdict = NF_ACCEPT
              }
            } else {
              console.log('untrusted');
              if (rules.incoming.untrusted_tcp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept untrusted');
                thisVerdict = NF_ACCEPT
              }
            }
          }
          break;
        case 17:
          console.log('udp');
          if (rules.incoming.global_udp.includes(packet.payload.dport.toString()) === true) {
            console.log('accept global');
            thisVerdict = NF_ACCEPT
          } else {
            if (interface.trusted) {
              console.log('trusted');
              if (rules.incoming.trusted_udp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept trusted');
                thisVerdict = NF_ACCEPT
              }
            } else {
              console.log('untrusted');
              if (rules.incoming.untrusted_udp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept untrusted');
                thisVerdict = NF_ACCEPT
              }
            }
          }
          break;
        default:
          console.log('other');
          if (interface.trusted) {
            console.log('trusted');
          } else {
            console.log('untrusted');
          }
          break
      }

      // Allow us to set a META MARK for requeue and reject.
      if (thisVerdict === NF_REJECT) {
        nfpacket.setVerdict(thisVerdict, 666);
      } else {
        nfpacket.setVerdict(4, 999);
      }

      // console.log(packet.identification);
    });
    interface.queueOut = nfq.createQueueHandler(parseInt('100' + interface.number), 65535, (nfpacket) => {
      console.log('packet received');
      let packet = new IPv4().decode(nfpacket.payload, 0);
      let thisVerdict = NF_REJECT;
      switch (packet.protocol) {
        case 6:
          console.log('tcp')
          if (rules.outgoing.global_tcp.includes(packet.payload.dport.toString()) === true) {
            console.log('accept global');
            thisVerdict = NF_ACCEPT
          } else {
            if (interface.trusted) {
              console.log('trusted');
              if (rules.outgoing.trusted_tcp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept trusted');
                thisVerdict = NF_ACCEPT
              }
            } else {
              console.log('untrusted');
              if (rules.outgoing.untrusted_tcp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept untrusted');
                thisVerdict = NF_ACCEPT
              }
            }
          }
          break;
        case 17:
          console.log('udp');
          if (rules.outgoing.global_udp.includes(packet.payload.dport.toString()) === true) {
            console.log('accept global');
            thisVerdict = NF_ACCEPT
          } else {
            if (interface.trusted) {
              console.log('trusted');
              if (rules.outgoing.trusted_udp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept trusted');
                thisVerdict = NF_ACCEPT
              }
            } else {
              console.log('untrusted');
              if (rules.outgoing.untrusted_udp.includes(packet.payload.dport.toString()) === true) {
                console.log('accept untrusted');
                thisVerdict = NF_ACCEPT
              }
            }
          }
          break;
        default:
          console.log('other');
          if (interface.trusted) {
            console.log('trusted');
          } else {
            console.log('untrusted');
          }
          break
      }

      // Allow us to set a META MARK for requeue and reject.
      if (thisVerdict === NF_REJECT) {
        nfpacket.setVerdict(thisVerdict, 666);
      } else {
        nfpacket.setVerdict(4, 999);
      }
    });
  })
}


// flushRules().then(
baseRules().then(
  setupInterfaces()
    .then(insertFinalCounters()
      .then(bindQueueHandlers()
      )
    )
).catch((err) => {
  console.log(err);
  flushRules().then(lockRules());
}
)
// )

