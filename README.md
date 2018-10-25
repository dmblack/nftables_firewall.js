# nftables_firewall.js
This is just a proof of concept / test to use NodeJS as a firewall.

# Disclaimer
Please consider that this is only an 'initial' demonstration / proof of
concept. I cannot take any responsibility of issues caused by using this.

It most definitely is NOT production ready.

I recommend you understand some basics of NFTables to otherwise reset your
rules to a safe state before continuing. That way, in the event of any
issue; you can quickly roll back to a 'safe' environment state.

On that note, however; I, personally; use it as my day to day firewall.

# Description
This is an example managing nfQueue packed from within NodeJS.

The overall 'result' is, effectively; a Firewall written in NodeJS.

To describe the topology;
1) Packet received by nftables, queued to nfqueue (userspace)
2) NodeJS listens on queue for packets, and handles appropriately.

This is achieved by using lipcap, nftables, and nfqueue.

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

## Note:
Some child dependencies have not been updated in some time failing builds
with later versions of NodeJS. For best results; use LTS/Carbon (8)

# Getting Started
Clone this repo within git, cd, and `npm install`.

Once running, you must initialize the app with sudo (Due to use of libpcap).

I personally use;

```sudo `which node` src/index.js```

# Usage
You can customize your rules within the *.json configuration files. To
ensure you take some responsibility, these are then loaded from a 'config'
folder in the root directory of the project. I symlink them;
```
mkdir config
cd config
ln -s ../src/config/rules.json .
ln -s ../src/config/interfaces.json .
ln -s ../src/config/rules-base.nft .
ln -s ../src/config/rules-locked.nft .
```

Output, when running, shows some basic stats of what has been achieved;

`Packets: 513 - IN: 39 (A: 0 - R: 39) - OUT: 474 (A: 264 - R: 210)`

Where A: Accepted, R: Rejected (Determined; anything other than accepted)

# Customisation
'Skeleton' Configuration files may be found in `src/config`, and should
then be placed in `config/` - as mentioned above'
* interfaces.json - specify your trusted, and untrusted, interfaces.
* rules.json - Specify what ports, in which 'trust' zones you want to allow
  * Note: Changes to this file are 'hot loaded'. Care should be taken.
* rules-base.nft - Is the 'initial' template of rules deployed. (Creates the
appropriate table, chains)
* rules-locked.nft - Is basically what the script 'should' fall back to
if there are any failures on init (SHOULD..)

# Further notes:
Interfaces are detected, with appropriate rules created, upon start. This
can be troublesome for non-persistent interfaces such as vpn (ppp/tun). I
restart the scrupt upon these interfaces becoming available. (And this will
be fixed in an upcoming release)
