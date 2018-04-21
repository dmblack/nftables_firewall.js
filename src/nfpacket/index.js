const actions = require('./actions');
const enums = require('./enums.js');

const nfpacket = (dependencies) => {
  if (Object.keys(dependencies).includes(['pcap', 'nfq'])) {
    return Object.assign(
      {},
      nfpacket,
      enums,
      actions(dependencies)
    )
  }

  return false;
}

module.exports = nfpacket;
