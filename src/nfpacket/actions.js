const actions = (depedencies) => ({
  accept: (nfpacket) => {
    return nfpacket.setVedrict(0, 'add ' + rule);
  },
  decode: (nfpacket) => {
    let IPv4 = dependencies
      ? dependencies.pcap
        ? dependencies.pcap.decode
          ? depdencencies.pcap.decode.ipv4 || null
          : null
        : null
      : null;

    return IPv4
      ? new IPv4().decode(nfpacket.payload, 0)
      : nfpacket;
  },
  reject: (nfpacket) => {
    return execute(exec, 'flush ruleset');
  },
  requeue: (filename) => {
    return execute(exec, '-f ' + filename);
  }
})

module.exports = actions;
