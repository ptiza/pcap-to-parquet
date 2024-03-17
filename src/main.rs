mod libpcap;
use libpcap::ffi;

/// Simple representation of the information
/// that we want to extract from a packet
#[derive(Default, Debug, Copy, Clone)]
struct Packet {
    src_ip: Option<std::net::IpAddr>,
    dst_ip: Option<std::net::IpAddr>,
    mm_ts: i64,
    mm_id: u16,
    mm_port: u8,
}

impl Packet {
    fn new() -> Self {
        Default::default()
    }

    /// Returns hardcoded parquet schema definition
    fn get_parquet_schema() -> String {
        String::from(
            "message Packet {
                required binary src_ip  (UTF8);
                required binary dst_ip  (UTF8);
                required int64  mm_ts;
                required int32  mm_id   (UINT_16);
                required int32  mm_port (UINT_8);
            }",
        )
    }

    /// Serializes the struct into row representation for parquet file
    fn serialize(&self) -> Vec<PacketField> {
        let mut ser_vec = Vec::new();
        match self.src_ip {
            Some(x) => ser_vec.push(PacketField::Text(x.to_string())),
            None => ser_vec.push(PacketField::Text("".to_string())),
        }
        match self.dst_ip {
            Some(x) => ser_vec.push(PacketField::Text(x.to_string())),
            None => ser_vec.push(PacketField::Text("".to_string())),
        }
        ser_vec.push(PacketField::Int64(self.mm_ts));
        ser_vec.push(PacketField::Int32(self.mm_id as i32));
        ser_vec.push(PacketField::Int32(self.mm_port as i32));

        return ser_vec;
    }
}

/// All desired packet fields can be represented
/// with these 3 types in a parquet schema
enum PacketField {
    Text(String),
    Int32(i32),
    Int64(i64),
}

fn main() {
    let input_path = std::env::args().nth(1).expect("no input given");
    let output_path = std::env::args().nth(2).expect("no output path given");
    let mut errbuf = [0 as core::ffi::c_char; ffi::PCAP_ERRBUF_SIZE as usize];

    let file = std::ffi::CString::new(input_path).unwrap();
    let handle = unsafe {
        ffi::pcap_open_offline_with_tstamp_precision(
            file.as_ptr(),
            ffi::PCAP_TSTAMP_PRECISION_NANO,
            errbuf.as_mut_ptr(),
        )
    };

    if handle.is_null() {
        println!("Error opening file: {:?}", unsafe {
            std::ffi::CStr::from_ptr(errbuf.as_ptr())
        });
        panic!();
    }

    // parquet file setup
    let schema =
        parquet::schema::parser::parse_message_type(&Packet::get_parquet_schema()).unwrap();

    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD(
            parquet::basic::ZstdLevel::try_new(3).unwrap(),
        ))
        .build();

    let path = std::path::Path::new(output_path.as_str());
    let file = std::fs::File::create(path).unwrap();
    let mut writer =
        parquet::file::writer::SerializedFileWriter::new(file, schema.into(), props.into())
            .unwrap();

    // loop over packets in pcap file
    loop {
        let mut pkt_header: ffi::pcap_pkthdr = Default::default();
        let packet = unsafe { ffi::pcap_next(handle, &mut pkt_header) };
        if packet.is_null() {
            break; // end of file
        }
        let packet = unsafe { std::slice::from_raw_parts(packet, pkt_header.len as _) };

        let mut packet_fields = Packet::new();

        parse_metamako_trailer(
            packet,
            &mut packet_fields,
            pkt_header.ts.tv_sec,
            pkt_header.len as _,
        );

        parse_ethernet_frame(packet, &mut packet_fields);

        // write the packet data to parquet file
        write_packet_to_parquet(packet_fields.serialize(), &mut writer);
    }

    // close the parquet file writer
    writer.close().unwrap();

    unsafe { ffi::pcap_close(handle) }
}

/// Check for metamako trailer by comparing capture timestamp with suspected metamako
/// timestamp and checking validity of ns field
///
/// If difference between pcap timestamp and suspected metamako timestamp
/// is smaller than 5min, trailer is likely present
///
/// Otherwise leaves fields empty
fn parse_metamako_trailer(packet: &[u8], packet_fields: &mut Packet, pcap_ts: i64, len: usize) {
    let mm_s = i32::from_be_bytes([
        packet[len - 16],
        packet[len - 15],
        packet[len - 14],
        packet[len - 13],
    ]);
    let mm_ns = i32::from_be_bytes([
        packet[len - 12],
        packet[len - 11],
        packet[len - 10],
        packet[len - 9],
    ]);

    if i64::abs(pcap_ts - mm_s as i64) < 5 * 60 && mm_ns < 1_000_000_000 {
        packet_fields.mm_id = u16::from_be_bytes([packet[len - 7], packet[len - 6]]);
        packet_fields.mm_port = u8::from_be_bytes([packet[len - 5]]);

        packet_fields.mm_ts = mm_s as i64 * 10i64.pow(9) + mm_ns as i64;
    }
}

fn parse_ipv4_packet(packet: &[u8], packet_fields: &mut Packet) {
    // let version = (packet[0] & 0xF0) >> 4;
    // let header_length = (packet[0] & 0x0F) * 4;
    // let total_length = u16::from_be_bytes([packet[2], packet[3]]);
    // let protocol = &packet[9];
    let src_addr = &packet[12..16];
    let dst_addr = &packet[16..20];

    packet_fields.src_ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        src_addr[0],
        src_addr[1],
        src_addr[2],
        src_addr[3],
    )));
    packet_fields.dst_ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        dst_addr[0],
        dst_addr[1],
        dst_addr[2],
        dst_addr[3],
    )));
}

/// Assuming Ethernet II frame format (14 bytes header)
fn parse_ethernet_frame(packet: &[u8], packet_fields: &mut Packet) {
    // let destination_mac = &packet[0..6];
    // let source_mac = &packet[6..12];
    let ether_type = u16::from_be_bytes([packet[12], packet[13]]);

    if ether_type == 0x8100 {
        let ether_type = u16::from_be_bytes([packet[16], packet[17]]);

        if ether_type == 0x800 {
            // IPv4 packet with VLAN tag
            parse_ipv4_packet(&packet[18..], packet_fields);
        } else {
            //TODO
            return;
        }
    } else if ether_type == 0x800 {
        // IPv4 packet
        parse_ipv4_packet(&packet[14..], packet_fields);
    } else {
        //TODO
        return;
    }
}

fn write_packet_to_parquet<W: std::io::Write>(
    packet_vec: Vec<PacketField>,
    writer: &mut parquet::file::writer::SerializedFileWriter<W>,
) where
    W: Send,
{
    // get row group writer
    let mut row_group_writer = writer.next_row_group().unwrap();
    for field in packet_vec.iter() {
        match field {
            PacketField::Text(text) => {
                if let Some(mut col_writer) = row_group_writer.next_column().unwrap() {
                    col_writer
                        .typed::<parquet::data_type::ByteArrayType>()
                        .write_batch(
                            &[parquet::data_type::ByteArray::from(text.as_bytes())],
                            None,
                            None,
                        )
                        .unwrap();
                    col_writer.close().unwrap();
                }
            }
            PacketField::Int64(i) => {
                if let Some(mut col_writer) = row_group_writer.next_column().unwrap() {
                    col_writer
                        .typed::<parquet::data_type::Int64Type>()
                        .write_batch(&[*i], None, None)
                        .unwrap();
                    col_writer.close().unwrap();
                }
            }
            PacketField::Int32(i) => {
                if let Some(mut col_writer) = row_group_writer.next_column().unwrap() {
                    col_writer
                        .typed::<parquet::data_type::Int32Type>()
                        .write_batch(&[*i], None, None)
                        .unwrap();
                    col_writer.close().unwrap();
                }
            }
        }
    }
    // close the row group writer after row is written
    row_group_writer.close().unwrap();
}
