use nix::sys::socket::{
    AddressFamily, SockFlag, SockProtocol, SockType, getsockopt, socket, sockopt,
};
use ping::linux::set_hop_limit;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
#[ignore = "requires CAP_NET_RAW and ICMP ping socket permission"]
fn applies_hop_limit_to_raw_and_ping_sockets() -> Result<(), Box<dyn Error>> {
    let configurations = [
        (
            AddressFamily::Inet,
            SockProtocol::Icmp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ),
        (
            AddressFamily::Inet6,
            SockProtocol::IcmpV6,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ),
    ];

    for (family, protocol, destination) in configurations {
        for socket_type in [SockType::Raw, SockType::Datagram] {
            let fd = socket(family, socket_type, SockFlag::empty(), protocol)?;
            set_hop_limit(&fd, destination, 23)?;
            let applied = match destination {
                IpAddr::V4(_) => getsockopt(&fd, sockopt::Ipv4Ttl)?,
                IpAddr::V6(_) => getsockopt(&fd, sockopt::Ipv6Ttl)?,
            };

            assert_eq!(applied, 23);
        }
    }

    Ok(())
}
