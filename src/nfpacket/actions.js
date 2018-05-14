const actions = (dependencies) => (state) => ({
  accept: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_ACCEPT)
      : false
  },
  reject: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_REJECT)
      : false
  },
  requeue: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_REQUEUE)
      : false
  }
})

module.exports = actions;
