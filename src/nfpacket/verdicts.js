module.exports = (dependencies) => (state) => ({
  accept: () => {
    return state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_ACCEPT, state.mark)
      : false;
  },
  reject: () => {
    // This allows us to admin-prohibit and immediately reject outgoing, intead of droop (timeout).
    if (state.direction === 'outgoing') {
      return state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, 777);
    } else {
      return state.nfpacket
        ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_DROP, state.mark)
        : false;
    }
  },
  requeue: () => {
    return state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, state.mark)
      : false;
  },
  getVerdict: () => {
    switch (state.verdict) {
      case state.enums.netfilterVerdict.NF_ACCEPT:
        return state.verdicts.accept;
      case state.enums.netfilterVerdict.NF_REPEAT:
        return state.verdicts.requeue;
      default:
        return state.verdicts.reject;
    }
  }
});
