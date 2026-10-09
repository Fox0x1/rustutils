use std::net::IpAddr;
use std::time::Duration;

pub fn ping_header(target: &str, destination: IpAddr, payload_size: usize) -> String {
    match destination {
        IpAddr::V4(address) => format!(
            "PING {target} ({address}) {payload_size}({}) bytes of data.",
            payload_size + 28
        ),
        IpAddr::V6(address) => format!("PING {target} ({address}) {payload_size} data bytes"),
    }
}

pub fn reply_line(
    source: IpAddr,
    sequence: u16,
    hop_limit: Option<u8>,
    elapsed: Duration,
    packet_size: usize,
) -> String {
    let time_ms = elapsed.as_secs_f64() * 1000.0;
    match source {
        IpAddr::V4(address) => match hop_limit {
            Some(ttl) => format!(
                "{packet_size} bytes from {address}: icmp_seq={sequence} ttl={ttl} time={time_ms:.3} ms"
            ),
            None => format!(
                "{packet_size} bytes from {address}: icmp_seq={sequence} time={time_ms:.3} ms"
            ),
        },
        IpAddr::V6(address) => match hop_limit {
            Some(hop_limit) => format!(
                "{packet_size} bytes from {address}: icmp_seq={sequence} hlim={hop_limit} time={time_ms:.3} ms"
            ),
            None => format!(
                "{packet_size} bytes from {address}: icmp_seq={sequence} time={time_ms:.3} ms"
            ),
        },
    }
}
