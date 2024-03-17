# pcap-to-parquet

Proof-of-concept on how to extract packet information from pcap files using [`libpcap`](https://github.com/the-tcpdump-group/libpcap),
and write them into a Parquet file using the [`parquet`](https://docs.rs/parquet/latest/parquet) crate.

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
Output example:
```
>>> SELECT * FROM 'output.parquet' LIMIT 10
┌─────────────────┬─────────────────┬──────────┬──────────┬──────────┬─────────────────────┬────────┬─────────┐
│     src_ip      │     dst_ip      │ protocol │ src_port │ dst_port │        mm_ts        │ mm_id  │ mm_port │
│     varchar     │     varchar     │ varchar  │  uint16  │  uint16  │        int64        │ uint16 │  uint8  │
├─────────────────┼─────────────────┼──────────┼──────────┼──────────┼─────────────────────┼────────┼─────────┤
│ 192.168.203.132 │ 192.168.203.2   │ UDP      │    39802 │       53 │ 1454635868495676994 │    165 │      14 │
│ 192.168.203.2   │ 192.168.203.132 │ UDP      │       53 │    39802 │ 1454635868497343063 │    165 │      14 │
│ 192.168.203.132 │ 10.10.10.109    │ ICMP     │     NULL │     NULL │ 1454635868497664928 │    165 │      14 │
│ 10.10.10.109    │ 192.168.203.132 │ ICMP     │     NULL │     NULL │ 1454635868498073101 │    165 │      14 │
│ 192.168.203.132 │ 192.168.203.2   │ UDP      │    45812 │       53 │ 1454635868498310089 │    165 │      14 │
│ 192.168.203.2   │ 192.168.203.132 │ UDP      │       53 │    45812 │ 1454635868499620914 │    165 │      14 │
│ 192.168.203.132 │ 10.10.10.109    │ ICMP     │     NULL │     NULL │ 1454635869499041080 │    165 │      14 │
│ 10.10.10.109    │ 192.168.203.132 │ ICMP     │     NULL │     NULL │ 1454635869499706029 │    165 │      14 │
│ 192.168.203.132 │ 192.168.203.2   │ UDP      │    36470 │       53 │ 1454635869500020027 │    165 │      14 │
│ 192.168.203.2   │ 192.168.203.132 │ UDP      │       53 │    36470 │ 1454635869501637935 │    165 │      14 │
├─────────────────┴─────────────────┴──────────┴──────────┴──────────┴─────────────────────┴────────┴─────────┤
│ 10 rows                                                                                           8 columns │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

Build using
```
cargo build --release
```
