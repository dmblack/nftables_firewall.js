const rules = require('./rules');

const nft = (dependencies) => {
  if (Object.keys(dependencies).includes('exec')) {
    return Object.assign(
      {},
      nft,
      rules(dependencies.exec)
    );
  }

  return false;
};

module.exports = nft;
