module.exports = (dependencies) => (state) => ({
  accept: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_ACCEPT, state.mark)
      : false
  },
  reject: () => {
    // This allows us to admin-prohibit and immediately reject outgoing, intead of droop (timeout).
    if (state.direction === 'outgoing') {
      state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, 777)
    } else {
      state.nfpacket
        ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_DROP, state.mark)
        : false
    }
  },
  requeue: () => {
    state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, state.mark)
      : false
  },
  getVerdict: () => {
    switch (state.verdict) {
      case state.enums.netfilterVerdict.NF_ACCEPT:
        return state.verdicts.accept;
        break;
      case state.enums.netfilterVerdict.NF_REPEAT:
        return state.verdicts.requeue;
        break;
      default:
        return state.verdicts.reject;
        break;
    }
  }
})
