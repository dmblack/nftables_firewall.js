const actions = (depedencies) => ({
  accept: (nfpacket) => {
    return nfpacket.setVedrict(0, 'add ' + rule);
  },
  reject: (nfpacket) => {
    nfpacket.setVerdict(this.enums.NF_REJECT);
    return this;
  },
  requeue: (filename) => {
    return execute(exec, '-f ' + filename);
  }
})

module.exports = actions;
