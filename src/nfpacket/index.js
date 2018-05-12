const actions = require('./actions');
const encoding = require('./encoding');
const enums = require('./enums.js');

module.exports = (dependencies) => (nfpacket) => {
  if (Object.keys(dependencies).includes('nfq') && Object.keys(dependencies).includes('pcapIPv4')) {
    return Object.assign(
      nfpacket,
      { actions: actions(dependencies) },
      { encoding: encoding(dependencies.pcapIPv4)(nfpacket) },
      { enum: enums },
      { decoded: undefined }
    );
  }

  return false;
}
