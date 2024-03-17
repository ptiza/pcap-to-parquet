# pcap-to-parquet

Proof-of-concept on how to extract packet information from pcap files using `libpcap`,
and write them into a Parquet file using the `parquet` crate.

It also supports Metamako Ethernet trailer, tested with 
[`metamako_trailer.pcap`](https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/metamako_trailer.pcap) file
from the Wireshark sample captures.

Usage is:

```
pcap-to-parquet <input-filepath> <output-filepath>
```

E.g.
```
pcap-to-parquet metamako_trailer.pcap output.parquet
```

Build using
```
cargo build --release
```
