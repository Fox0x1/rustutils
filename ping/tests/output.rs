use ping::output::{ping_header, reply_line};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[test]
fn formats_linux_style_ipv4_header() {
    assert_eq!(
        ping_header("1.1.1.1", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 56),
        "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data."
    );
}

#[test]
fn formats_ipv4_reply_with_ttl() {
    assert_eq!(
        reply_line(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            1,
            Some(59),
            Duration::from_micros(54_200),
            64,
        ),
        "64 bytes from 1.1.1.1: icmp_seq=1 ttl=59 time=54.200 ms"
    );
}

#[test]
fn formats_ipv6_reply_with_hop_limit() {
    assert_eq!(
        reply_line(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            2,
            Some(61),
            Duration::from_micros(12_340),
            64,
        ),
        "64 bytes from ::1: icmp_seq=2 hlim=61 time=12.340 ms"
    );
}

#[test]
fn formats_replies_without_hop_limit() {
    assert_eq!(
        reply_line(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            3,
            None,
            Duration::from_millis(1),
            64,
        ),
        "64 bytes from 1.1.1.1: icmp_seq=3 time=1.000 ms"
    );
}

#[test]
fn formats_linux_style_ipv6_header() {
    assert_eq!(
        ping_header("::1", IpAddr::V6(Ipv6Addr::LOCALHOST), 56),
        "PING ::1 (::1) 56 data bytes"
    );
}
