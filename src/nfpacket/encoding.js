const encoding = (dependencies) => (nfpacket) => ({
  decode: () => {
    let IPv4 = dependencies || null;

    nfpacket.nfpacketDecoded = IPv4
      ? new IPv4().decode(nfpacket.payload, 0)
      : false;
  }
})

module.exports = encoding;
