const netfilterVerdict = {
  NF_DROP: 0,
  NF_ACCEPT: 1,
  NF_STOLEN: 2,
  NF_QUEUE: 3,
  NF_REPEAT: 4,
  NF_STOP: 5
}

const protocols = {
  PC_ICMP: 1,
  PC_IGMP: 2,
  PC_TCP: 6,
  PC_UDP: 17
}

const ruleVerdict = {
  accept: netfilterVerdict.NF_ACCEPT,
  drop: netfilterVerdict.NF_DROP,
  reject: netfilterVerdict.NF_DROP
}

module.exports = {
  netfilterVerdict,
  protocols,
  ruleVerdict
}

  /*
module.exports = {
  netfilterVerdict: {
    // These are the NFQUEUE result handler options.
    NF_DROP: 0,
    NF_ACCEPT: 1, // Accept packet (but no longer seen / disowned by conntrack,
    NF_STOLEN: 2,
    NF_QUEUE: 3,
    NF_REPEAT: 4, // Requeue packet (Which we then use a mark to determine the action,
    NF_STOP: 5
  },
  protocols: {
    // Protocol Numbers can be found here, however; libpcap has limited support..
    //   https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    PC_ICMP: 1,
    PC_IGMP: 2,
    PC_TCP: 6,
    PC_UDP: 17
  },
  ruleVerdict: {
    accept: this.netfilterVerdict.NF_ACCEPT,
    drop: this.netfilterVerdict.NF_DROP,
    reject: this.netfilterVerdict.NF_DROP
  }
};
*/
