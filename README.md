# Any2tcp/udp

I wrote these two sources in order to test/check/evade a stupid firewall which is checking only the IP protocol "payload type" field, but it's not checking it for a minimum validity (eg. minimum required headers, etc).

This can be used to use a protocol where it's blocked by a stupid firewall. For example, UDP can be "masked" as TCP on source by changing the relevant IP field, and then changed back to UDP on the target (or intermediate host).

How to use it? Compile, launch and add a NFQUEUE target to iptables/nftables.

## Which is the difference between this and udp2raw?

[udp2raw](https://github.com/wangyu-/udp2raw-tunnel) is encapsulating traffic in other protocols, adding relevant fields (eg. TCP headers), so it's more stealthy and more compatible. The code I wrote instead is not meant to be a replacement of udp2raw, but a basic masking tool for firewall testing.
