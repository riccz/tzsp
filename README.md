## TZSP ##

This is a simple CLI tool to listen for TZSP packets and convert them to PCAP.
A common way to use it is:

```shell
tzsp | wireshark -i - -k
```

It can also save to file:

```shell
tzsp -o capture.pcap
```
