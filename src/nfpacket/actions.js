const actions = (dependencies) => (state) => ({
  accept: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_ACCEPT)
      : false
  },
  reject: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_DROP)
      : false
  },
  requeue: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(dependencies.enums.NF_REPEAT)
      : false
  }
})

module.exports = actions;
