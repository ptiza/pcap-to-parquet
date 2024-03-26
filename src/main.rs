use pcap_parser::traits::PcapReaderIterator;

/// Simple representation of the information
/// that we want to extract from a packet
#[derive(Default, Debug, Clone)]
struct Packet {
    src_ip: Option<String>,
    dst_ip: Option<String>,
    len: Option<u32>,
    protocol: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    mm_ts: Option<i64>,
    mm_id: Option<u16>,
    mm_port: Option<u8>,
}

impl Packet {
    fn new() -> Self {
        Default::default()
    }

    /// Serializes the struct into row representation for parquet file
    fn serialize(self) -> arrow_array::RecordBatch {
        let src_ip: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::StringArray::from(vec![self.src_ip]));
        let dst_ip: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::StringArray::from(vec![self.dst_ip]));
        let len: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::UInt32Array::from(vec![self.len]));
        let protocol: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::StringArray::from(vec![self.protocol]));
        let src_port: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::UInt16Array::from(vec![self.src_port]));
        let dst_port: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::UInt16Array::from(vec![self.dst_port]));
        let mm_ts: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::Int64Array::from(vec![self.mm_ts]));
        let mm_id: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::UInt16Array::from(vec![self.mm_id]));
        let mm_port: arrow_array::ArrayRef =
            std::sync::Arc::new(arrow_array::UInt8Array::from(vec![self.mm_port]));

        arrow_array::RecordBatch::try_from_iter(vec![
            ("src_ip", src_ip),
            ("dst_ip", dst_ip),
            ("len", len),
            ("protocol", protocol),
            ("src_port", src_port),
            ("dst_port", dst_port),
            ("mm_ts", mm_ts),
            ("mm_id", mm_id),
            ("mm_port", mm_port),
        ])
        .unwrap()
    }
}

fn main() {
    let input_path = std::env::args().nth(1).expect("no input given");
    let output_path = std::env::args().nth(2).expect("no output path given");

    // pcap file setup
    let pcap_file = std::fs::File::open(input_path).unwrap();
    let mut pcap_reader =
        pcap_parser::LegacyPcapReader::new(65536, pcap_file).expect("LegacyPcapReader");

    // parquet file setup
    let output_path = std::path::Path::new(output_path.as_str());
    let parquet_file = std::fs::File::create(output_path).unwrap();
    let schema = Packet::serialize(Packet::new()).schema();
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD(
            parquet::basic::ZstdLevel::try_new(3).unwrap(),
        ))
        .set_writer_version(parquet::file::properties::WriterVersion::PARQUET_2_0)
        .build();

    let mut parquet_writer =
        parquet::arrow::ArrowWriter::try_new(parquet_file, schema, Some(props)).unwrap();

    // loop over packets in pcap file
    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    pcap_parser::PcapBlockOwned::LegacyHeader(_) => (),
                    pcap_parser::PcapBlockOwned::Legacy(b) => {
                        let mut packet_fields = Packet::new();
                        packet_fields.len = Some(b.origlen);
                        // min trailer size
                        if b.origlen >= 16 {
                            extract_all_metamako_trailers(
                                b.data,
                                &mut packet_fields,
                                b.ts_sec as i64,
                                b.origlen as _,
                            );
                        }

                        parse_ethernet_frame(b.data, &mut packet_fields);

                        // write the packet data to parquet file
                        parquet_writer
                            .write(&packet_fields.serialize())
                            .expect("Writing batch");
                    }
                    pcap_parser::PcapBlockOwned::NG(_) => unreachable!(),
                }
                pcap_reader.consume(offset);
            }
            Err(pcap_parser::PcapError::Eof) => break,
            Err(pcap_parser::PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    // close the parquet file writer
    parquet_writer.close().unwrap();
}

/// A trailing 4-byte FCS might be present, or multiple trailers due to aggregation.
/// We don't know about this, so we have to try at least twice.
/// If one trailer is found, search for additional trailers.
/// The information in the first trailer will be saved in `packet_fields`.
fn extract_all_metamako_trailers(
    packet: &[u8],
    packet_fields: &mut Packet,
    pcap_ts: i64,
    len: usize,
) {
    if let Some(tr_len) = parse_metamako_trailer(packet, packet_fields, pcap_ts, len) {
        // one trailer found, check for additional trailers
        let mut i = tr_len;
        while i <= len - tr_len {
            i += parse_metamako_trailer(packet, packet_fields, pcap_ts, len - i).unwrap_or(1);
        }
    // trailing FCS (4 bytes) might be present
    } else if let Some(tr_len) = parse_metamako_trailer(packet, packet_fields, pcap_ts, len - 4) {
        // one trailer found, check for additional trailers
        let mut i = tr_len;
        while i <= len - tr_len - 4 {
            i += parse_metamako_trailer(packet, packet_fields, pcap_ts, len - i - 4).unwrap_or(1);
        }
    }
}

/// Check for metamako trailer by comparing capture timestamp with suspected metamako
/// timestamp and checking validity of ns field
///
/// If difference between pcap timestamp and suspected metamako timestamp
/// is smaller than 5min, trailer is likely present
///
/// Otherwise leaves fields empty
fn parse_metamako_trailer(
    packet: &[u8],
    packet_fields: &mut Packet,
    pcap_ts: i64,
    len: usize,
) -> Option<usize> {
    let mm_s = i32::from_be_bytes(
        packet[len - 12..len - 8]
            .try_into()
            .expect("incorrect slice len"),
    );
    let mm_ns = i32::from_be_bytes(
        packet[len - 8..len - 4]
            .try_into()
            .expect("incorrect slice len"),
    );

    if i64::abs(pcap_ts - mm_s as i64) < 5 * 60 && mm_ns < 1_000_000_000 {
        packet_fields.mm_id = Some(u16::from_be_bytes([packet[len - 3], packet[len - 2]]));
        packet_fields.mm_port = Some(u8::from_be_bytes([packet[len - 1]]));
        packet_fields.mm_ts = Some(mm_s as i64 * 10i64.pow(9) + mm_ns as i64);
        // min trailer length
        Some(16)
    } else {
        None
    }
}

fn parse_ipv4_packet(packet: &[u8], packet_fields: &mut Packet) {
    // let version = (packet[0] & 0xF0) >> 4;
    let header_length = (packet[0] & 0x0F) * 4;
    // let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    let protocol = &packet[9];
    let src_addr: [u8; 4] = packet[12..16].try_into().expect("incorrect slice len");
    let dst_addr: [u8; 4] = packet[16..20].try_into().expect("incorrect slice len");

    packet_fields.src_ip =
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(src_addr)).to_string());
    packet_fields.dst_ip =
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(dst_addr)).to_string());

    match protocol {
        1 => packet_fields.protocol = Some(String::from("ICMP")),
        2 => packet_fields.protocol = Some(String::from("IGMP")),
        6 => {
            packet_fields.protocol = Some(String::from("TCP"));
            parse_tcp_packet(&packet[header_length as _..], packet_fields)
        }
        17 => {
            packet_fields.protocol = Some(String::from("UDP"));
            parse_udp_packet(&packet[header_length as _..], packet_fields)
        }
        _ => (),
    }
}

fn parse_udp_packet(packet: &[u8], packet_fields: &mut Packet) {
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);

    packet_fields.src_port = Some(src_port);
    packet_fields.dst_port = Some(dst_port);

    //TODO
}

fn parse_tcp_packet(packet: &[u8], packet_fields: &mut Packet) {
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);

    packet_fields.src_port = Some(src_port);
    packet_fields.dst_port = Some(dst_port);

    //TODO
}

/// Assuming Ethernet II frame format (14 bytes header)
fn parse_ethernet_frame(packet: &[u8], packet_fields: &mut Packet) {
    // let destination_mac = &packet[0..6];
    // let source_mac = &packet[6..12];
    let ether_type = u16::from_be_bytes([packet[12], packet[13]]);

    match ether_type {
        // IPv4 packet
        0x800 => parse_ipv4_packet(&packet[14..], packet_fields),
        0x8100 => {
            let ether_type = u16::from_be_bytes([packet[16], packet[17]]);
            match ether_type {
                // IPv4 packet with VLAN tag
                0x800 => parse_ipv4_packet(&packet[18..], packet_fields),
                _ => (),
            }
        }
        _ => (),
    }
}
