const encoding = (dependencies) => (state) => ({
  decode: () => {
    let IPv4 = dependencies || null;

    state.nfpacketDecoded = IPv4
      ? new IPv4().decode(state.nfpacket.payload, 0)
      : false;
  }
})

module.exports = encoding;
