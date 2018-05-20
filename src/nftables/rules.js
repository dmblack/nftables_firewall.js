function execute (exec, command) {
  return new Promise((resolve, reject) => {
    exec('nft ' + command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        if (stdout) {
          resolve(stdout);
        } else {
          resolve(stderr);
        }
      }
    });
  });
}

function executeReturnHandle (exec, command) {
  return new Promise((resolve, reject) => {
    exec('nft --echo --handle ' + command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        if (stdout) {
          let unparsedResult = stdout.split(' ');
          resolve(unparsedResult[unparsedResult.length - 1]);
        } else {
          resolve(stderr);
        }
      }
    });
  });
}

const rules = (exec) => ({
  add: (rule) => {
    return execute(exec, 'add ' + rule);
  },
  addWithHandle: (rule) => {
    return executeReturnHandle(exec, 'add ' + rule);
  },
  flush: () => {
    return execute(exec, 'flush ruleset');
  },
  inject: (filename) => {
    return execute(exec, '-f ' + filename);
  },
  list: () => {
    return execute(exec, 'list ruleset');
  },
  removeByTableSetChainHandle: (table, set, chain, handle) => {
    return execute(exec, 'delete rule table ' + table + ' ' + set + ' ' + chain + ' ' + handle);
  }
});

module.exports = rules;
