use std::net::{Ipv4Addr, Ipv6Addr};

pub const DEFAULT_PAYLOAD_SIZE: usize = 56;

#[derive(Debug, PartialEq, Eq)]
pub struct EchoReply {
    pub sequence: u16,
    pub hop_limit: Option<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    Truncated,
    InvalidVersion,
    InvalidHeaderLength,
    InvalidPacketLength,
    InvalidIpv4Checksum,
    InvalidIcmpChecksum,
}

pub fn default_payload(token: u128) -> [u8; DEFAULT_PAYLOAD_SIZE] {
    let mut payload = [0u8; DEFAULT_PAYLOAD_SIZE];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = index as u8;
    }
    payload[..16].copy_from_slice(&token.to_be_bytes());
    payload
}

pub fn build_echo_request_v4(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = echo_request(8, identifier, sequence, payload);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub fn build_echo_request_v6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = echo_request(128, identifier, sequence, payload);
    let checksum = icmpv6_checksum(source, destination, &packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

pub fn parse_echo_reply_v4(
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Option<EchoReply>, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::Truncated);
    }
    if packet[0] >> 4 != 4 {
        return Err(PacketError::InvalidVersion);
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 {
        return Err(PacketError::InvalidHeaderLength);
    }
    if packet.len() < header_len {
        return Err(PacketError::Truncated);
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || total_len > packet.len() {
        return Err(PacketError::InvalidPacketLength);
    }
    if packet[9] != 1 || is_fragmented_ipv4(packet) {
        return Ok(None);
    }
    if Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]) != expected_source
        || Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]) != expected_destination
    {
        return Ok(None);
    }
    if internet_checksum(&packet[..header_len]) != 0 {
        return Err(PacketError::InvalidIpv4Checksum);
    }

    let message = &packet[header_len..total_len];
    let reply = parse_echo_reply_v4_message(message, identifier, sequence, payload)?;
    Ok(reply.map(|mut reply| {
        reply.hop_limit = Some(packet[8]);
        reply
    }))
}

pub fn parse_echo_reply_v4_message(
    message: &[u8],
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Option<EchoReply>, PacketError> {
    if message.len() < 8 {
        return Err(PacketError::Truncated);
    }
    let Some(reply) = parse_echo_fields(message, 0, identifier, sequence, payload)? else {
        return Ok(None);
    };
    if internet_checksum(message) != 0 {
        return Err(PacketError::InvalidIcmpChecksum);
    }
    Ok(Some(reply))
}

pub fn parse_echo_reply_v6(
    message: &[u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Option<EchoReply>, PacketError> {
    if message.len() < 8 {
        return Err(PacketError::Truncated);
    }
    let Some(reply) = parse_echo_fields(message, 129, identifier, sequence, payload)? else {
        return Ok(None);
    };
    if icmpv6_checksum(source, destination, message) != 0 {
        return Err(PacketError::InvalidIcmpChecksum);
    }
    Ok(Some(reply))
}

fn is_fragmented_ipv4(packet: &[u8]) -> bool {
    packet[6] & 0x20 != 0 || packet[6] & 0x1f != 0 || packet[7] != 0
}

fn echo_request(kind: u8, identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.extend_from_slice(&[kind, 0, 0, 0]);
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn parse_echo_fields(
    message: &[u8],
    expected_kind: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Option<EchoReply>, PacketError> {
    if message.len() < 8 {
        return Err(PacketError::Truncated);
    }
    if message[0] != expected_kind || message[1] != 0 {
        return Ok(None);
    }

    let received_identifier = u16::from_be_bytes([message[4], message[5]]);
    let received_sequence = u16::from_be_bytes([message[6], message[7]]);
    if received_identifier != identifier
        || received_sequence != sequence
        || &message[8..] != payload
    {
        return Ok(None);
    }

    Ok(Some(EchoReply {
        sequence: received_sequence,
        hop_limit: None,
    }))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u64::from(u16::from_be_bytes(*chunk));
    }
    if let Some(byte) = remainder.first() {
        sum += u64::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + message.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 58]);
    pseudo_header.extend_from_slice(message);
    internet_checksum(&pseudo_header)
}
