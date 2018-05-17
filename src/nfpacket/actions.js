const actions = (dependencies) => (state) => ({
  accept: (mark) => {
    state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_ACCEPT, mark)
      : false
  },
  reject: (mark) => {
    // This allows us to admin-prohibit and immediately reject outgoing, intead of droop (timeout).
    if (state.direction === 'outgoing') {
      state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, 777)
    } else {
      state.nfpacket
        ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_DROP, mark)
        : false
    }
  },
  requeue: (mark) => {
    state.nfpacket
      ? state.nfpacket.setVerdict(state.enums.netfilterVerdict.NF_REPEAT, mark)
      : false
  },
  verdict: (verdict, mark) => {
    switch (verdict) {
      case state.enums.netfilterVerdict.NF_ACCEPT:
        return state.actions.accept;
        break;
      case state.enums.netfilterVerdict.NF_REPEAT:
        return state.actions.requeue;
        break;
      default:
        return state.actions.reject;
        break;
    }
  }
})

module.exports = actions;
