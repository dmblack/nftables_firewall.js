const actions = require('./actions');
const encoding = require('./encoding');
const enums = require('./enums.js');

module.exports = (dependencies) => (nfpacket) => {
  let state = {
    nfpacket: nfpacket,
    enums: enums
  }
  if (Object.keys(dependencies).includes('nfq') && Object.keys(dependencies).includes('pcapIPv4')) {
    return Object.assign(
      {},
      {
        actions: actions(dependencies)(state),
        encoding: encoding(dependencies.pcapIPv4)(state),
        state
      }
    );
  }

  return false;
}
