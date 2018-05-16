const actions = require('./actions');
const encoding = require('./encoding');
const enums = require('./enums.js');
const statable = require('./../state');

module.exports = (dependencies) => (nfpacket) => {
  let state = statable('mutable')({
    direction: undefined,
    enums: enums,
    interface: undefined,
    nfpacket: nfpacket,
  });

  if (Object.keys(dependencies).includes('nfq') && Object.keys(dependencies).includes('pcapIPv4')) {
    return Object.assign(
      state,
      {
        actions: actions(dependencies)(state),
        encoding: encoding(dependencies.pcapIPv4)(state)
      }
    );
  }

  return false;
}
