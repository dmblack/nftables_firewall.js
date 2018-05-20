const filesystem = require('./filesystem');

const actions = (dependencies) => {
  if (Object.keys(dependencies).includes('fs')) {
    return Object.assign(
      {},
      actions,
      filesystem(dependencies.fs)
    );
  }

  return false;
};

module.exports = actions;
