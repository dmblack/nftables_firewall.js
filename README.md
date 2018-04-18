# nftables_firewall.js
This is just a proof of concept / test to use NodeJS as a firewall.

# Disclaimer
Please consider that this is only an 'initial' demonstration / proof of
concept. I cannot take any responsibility of issues caused by using this.

It most definitely is NOT production ready.

I recommend you understand some basics of NFTables to otherwise reset your
rules to a safe state before continuing. That way, in the event of any
issue; you can quickly roll back to a 'safe' environment state.

# Description
This is an example of using NodeJS, and there in; javascript as a firewall.

A more so accurate description may also be;
nfqueued packets, from nftables, managed by javascript.

This is done by using lipcap, and nfqueue (With appropriate nftables rules)
to queue packets to user space.

# Dependencies
* linux
* nftables

To successfully build some of the child dependencies with `npm install`, as
some build directly from sources like github - you may require things like
(From a Debian system)
* build-essential
* libpcacp-dev
* libnetfilter-queue-dev
* libnfnetlink-dev

# Getting Started
Clone this repo within git, cd, and `npm install`.

Once running, you must initialize the app with sudo (Due to use of libpcap).

I personally use;

```sudo `which node` src/index.js```

# Usage
You can customize your rules within the *.json configuration files.

In this current state; the app uses META MARKS to demonstrate the firewall 
is actually functioning. The overall flow is;
 - Packet is picked up by nftables.
 - Packet runs over rules supplied by nodejs, marked (666 reject, 999 accept)
 - Packet is then requeued back to nftables (And accepted/dropped by meta
 filters)

Output, when running, shows some basic stats of what has been achieved;

`Connections - Accepted: 925 (I: 0 O: 925) - Rejected: 66 (I: 4 O: 62)`

Where; I = Incomming, O = Outgoing.

# Customisation
Configuration files may be found in src/config.
* interfaces.json - specify your trusted, and untrusted, interfaces.
* rules.json - Specify what ports, in which 'trust' zones you want to allow
* * Note: Changes to this file are 'hot loaded'. Care should be taken.
* base.rules - Is the 'initial' template of rules deployed. (Creates the 
appropriate table, chains)
* locked.rules - Is basically what the script 'should' fall back to if there
are any failures on init (SHOULD..)