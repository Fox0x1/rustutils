use ping::packet::{
    DEFAULT_PAYLOAD_SIZE, PacketError, build_echo_request_v4, build_echo_request_v6,
    default_payload, parse_echo_reply_v4, parse_echo_reply_v4_message, parse_echo_reply_v6,
};
use std::net::{Ipv4Addr, Ipv6Addr};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u64::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_echo_reply(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = build_echo_request_v4(identifier, sequence, payload);
    icmp[0] = 0;
    icmp[2..4].fill(0);
    let icmp_checksum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    packet[8] = 49;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = checksum(&packet);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}

fn ipv6_echo_reply(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut message = build_echo_request_v6(destination, source, identifier, sequence, payload);
    message[0] = 129;
    message[2..4].fill(0);
    let mut pseudo_header = Vec::with_capacity(40 + message.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 58]);
    pseudo_header.extend_from_slice(&message);
    let icmp_checksum = checksum(&pseudo_header);
    message[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
    message
}

#[test]
fn builds_ipv4_echo_request_and_valid_checksum() {
    let message = build_echo_request_v4(0x1234, 7, b"abc");

    assert_eq!(&message[..8], &[8, 0, 0x21, 0x62, 0x12, 0x34, 0, 7]);
    assert_eq!(checksum(&message), 0);
}

#[test]
fn builds_ipv6_echo_request_with_valid_pseudo_header_checksum() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let message = build_echo_request_v6(source, destination, 3, 12, b"v6");
    let mut pseudo_header = Vec::with_capacity(40 + message.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 58]);
    pseudo_header.extend_from_slice(&message);

    assert_eq!(&message[..2], &[128, 0]);
    assert_eq!(checksum(&pseudo_header), 0);
}

#[test]
fn default_payload_matches_linux_ping_data_size() {
    let payload = default_payload(0x0123456789abcdef0123456789abcdef);

    assert_eq!(DEFAULT_PAYLOAD_SIZE, 56);
    assert_eq!(payload.len(), 56);
    assert_eq!(
        &payload[..16],
        &0x0123456789abcdef0123456789abcdefu128.to_be_bytes()
    );
    assert_eq!(&payload[16..], &(16u8..56).collect::<Vec<_>>());
}

#[test]
fn parses_matching_ipv4_raw_reply_and_checks_addresses() {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::LOCALHOST;
    let packet = ipv4_echo_reply(source, destination, 0x4321, 9, b"probe");

    let parsed = parse_echo_reply_v4(&packet, source, destination, 0x4321, 9, b"probe");
    let wrong_source = parse_echo_reply_v4(
        &packet,
        Ipv4Addr::new(192, 0, 2, 2),
        destination,
        0x4321,
        9,
        b"probe",
    );

    assert!(
        matches!(parsed, Ok(Some(reply)) if reply.sequence == 9 && reply.hop_limit == Some(49))
    );
    assert_eq!(wrong_source, Ok(None));
}

#[test]
fn parses_matching_ipv4_ping_socket_reply() {
    let message = build_echo_request_v4(0x1234, 11, b"payload");
    let mut reply = message;
    reply[0] = 0;
    reply[2..4].fill(0);
    let icmp_checksum = checksum(&reply);
    reply[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let parsed = parse_echo_reply_v4_message(&reply, 0x1234, 11, b"payload");

    assert!(matches!(parsed, Ok(Some(reply)) if reply.sequence == 11 && reply.hop_limit.is_none()));
}

#[test]
fn parses_matching_ipv6_reply() {
    let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let destination = Ipv6Addr::LOCALHOST;
    let message = ipv6_echo_reply(source, destination, 8, 4, b"v6-data");

    let parsed = parse_echo_reply_v6(&message, source, destination, 8, 4, b"v6-data");

    assert!(matches!(parsed, Ok(Some(reply)) if reply.sequence == 4));
}

#[test]
fn rejects_truncated_and_malformed_packets() {
    assert_eq!(
        parse_echo_reply_v4(
            &[0; 10],
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            1,
            1,
            b""
        ),
        Err(PacketError::Truncated)
    );
    assert_eq!(
        parse_echo_reply_v4_message(&[0; 7], 1, 1, b""),
        Err(PacketError::Truncated)
    );
    assert_eq!(
        parse_echo_reply_v6(&[0; 7], Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 1, 1, b""),
        Err(PacketError::Truncated)
    );

    let mut invalid_checksum =
        ipv4_echo_reply(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 4, 5, b"bad");
    invalid_checksum[22] ^= 1;
    assert_eq!(
        parse_echo_reply_v4(
            &invalid_checksum,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            4,
            5,
            b"bad"
        ),
        Err(PacketError::InvalidIcmpChecksum)
    );

    let mut invalid_header =
        ipv4_echo_reply(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 4, 5, b"bad");
    invalid_header[8] ^= 1;
    assert_eq!(
        parse_echo_reply_v4(
            &invalid_header,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            4,
            5,
            b"bad"
        ),
        Err(PacketError::InvalidIpv4Checksum)
    );
}

#[test]
fn ignores_packets_for_other_probes() {
    let message = build_echo_request_v4(0x1234, 11, b"payload");
    let mut reply = message;
    reply[0] = 0;
    reply[2..4].fill(0);
    let icmp_checksum = checksum(&reply);
    reply[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    assert_eq!(
        parse_echo_reply_v4_message(&reply, 0x9999, 11, b"payload"),
        Ok(None)
    );
    assert_eq!(
        parse_echo_reply_v4_message(&reply, 0x1234, 12, b"payload"),
        Ok(None)
    );
    assert_eq!(
        parse_echo_reply_v4_message(&reply, 0x1234, 11, b"different"),
        Ok(None)
    );
}

#[test]
fn rejects_ipv6_reply_with_bad_checksum() {
    let source = Ipv6Addr::LOCALHOST;
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let mut message = ipv6_echo_reply(source, destination, 8, 4, b"v6-data");
    message[2] ^= 1;

    assert_eq!(
        parse_echo_reply_v6(&message, source, destination, 8, 4, b"v6-data"),
        Err(PacketError::InvalidIcmpChecksum)
    );
}

#[test]
fn ignores_non_echo_packets_without_counting_their_bad_icmp_checksum() {
    let mut unrelated = build_echo_request_v4(0x9999, 8, b"other");
    unrelated[0] = 3;
    unrelated[2..4].fill(0);

    assert_eq!(
        parse_echo_reply_v4_message(&unrelated, 0x1234, 8, b"probe"),
        Ok(None)
    );
}

#[test]
fn ignores_ipv4_fragments_but_accepts_dont_fragment() {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let destination = Ipv4Addr::LOCALHOST;
    let mut packet = ipv4_echo_reply(source, destination, 0x4321, 9, b"probe");

    packet[6] = 0x20;
    packet[10..12].fill(0);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    assert_eq!(
        parse_echo_reply_v4(&packet, source, destination, 0x4321, 9, b"probe"),
        Ok(None)
    );

    packet[6] = 0x40;
    packet[10..12].fill(0);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    assert!(matches!(
        parse_echo_reply_v4(&packet, source, destination, 0x4321, 9, b"probe"),
        Ok(Some(_))
    ));
}
