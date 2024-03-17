#![allow(non_camel_case_types, non_snake_case, dead_code)]

pub const PCAP_TSTAMP_PRECISION_MICRO: u32 = 0;
pub const PCAP_TSTAMP_PRECISION_NANO: u32 = 1;

pub const PCAP_ERRBUF_SIZE: u32 = 256;

pub type pcap_t = *mut core::ffi::c_void;
pub type pcap_pkthdr = pcap_pkthdr_t;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct pcap_pkthdr_t {
    pub ts: timeval,
    pub caplen: core::ffi::c_uint,
    pub len: core::ffi::c_uint,
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct timeval {
    pub tv_sec: core::ffi::c_long,
    pub tv_usec: core::ffi::c_long,
}

extern "C" {
    pub fn pcap_open_offline_with_tstamp_precision(
        file: *const core::ffi::c_char,
        precision: u32,
        errbuf: *mut core::ffi::c_char,
    ) -> pcap_t;
    pub fn pcap_close(p: pcap_t);
    pub fn pcap_next(p: pcap_t, pkt_header: *mut pcap_pkthdr) -> *const core::ffi::c_uchar;
}

#[cfg(windows)]
#[link(name = "wpcap")]
extern "C" {}

#[cfg(not(windows))]
#[link(name = "pcap")]
extern "C" {}
