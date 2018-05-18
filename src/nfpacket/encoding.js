const encoding = (dependencies) => (state) => ({
  decode: () => {
    let IPv4 = dependencies || null;
    let nfpacketDecoded = IPv4
      ? new IPv4().decode(state.nfpacket.payload, 0)
      : false
    state.nfpacketDecoded = nfpacketDecoded;
    state.nfpacketDecoded.payloadDecoded = state.nfpacketDecoded.payload.toString();
  }
})

module.exports = encoding;
