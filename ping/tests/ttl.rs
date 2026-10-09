use nix::sys::socket::ControlMessageOwned;
use ping::config::parse_args;
use ping::linux::{
    HopLimitOption, hop_limit_from_control_messages, hop_limit_option, set_hop_limit,
};
use std::error::Error;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn selects_family_specific_hop_limit_options() {
    assert_eq!(
        hop_limit_option(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        HopLimitOption::Ipv4Ttl
    );
    assert_eq!(
        hop_limit_option(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        HopLimitOption::Ipv6UnicastHops
    );
}

#[test]
fn parsed_configuration_selects_the_matching_ip_option() -> Result<(), Box<dyn Error>> {
    let ipv4 = parse_args(["--ttl", "29", "127.0.0.1"].map(str::to_owned).into_iter())?
        .ok_or("expected IPv4 config")?;
    let ipv6 = parse_args(["--hop-limit", "47", "::1"].map(str::to_owned).into_iter())?
        .ok_or("expected IPv6 config")?;

    assert_eq!(ipv4.ttl, Some(29));
    assert_eq!(
        hop_limit_option(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        HopLimitOption::Ipv4Ttl
    );
    assert_eq!(ipv6.ttl, Some(47));
    assert_eq!(
        hop_limit_option(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        HopLimitOption::Ipv6UnicastHops
    );
    Ok(())
}

#[test]
fn reports_socket_option_failures() -> Result<(), Box<dyn Error>> {
    let file = File::open("/dev/null")?;

    assert!(set_hop_limit(&file, IpAddr::V4(Ipv4Addr::LOCALHOST), 31).is_err());
    assert!(set_hop_limit(&file, IpAddr::V6(Ipv6Addr::LOCALHOST), 31).is_err());
    Ok(())
}

#[test]
fn reads_ipv4_ttl_and_ipv6_hop_limit_control_messages() {
    assert_eq!(
        hop_limit_from_control_messages([ControlMessageOwned::Ipv4Ttl(59)].into_iter()),
        Some(59)
    );
    assert_eq!(
        hop_limit_from_control_messages([ControlMessageOwned::Ipv6HopLimit(41)].into_iter()),
        Some(41)
    );
}

#[test]
fn ignores_missing_or_invalid_hop_limit_values() {
    assert_eq!(hop_limit_from_control_messages(std::iter::empty()), None);
    assert_eq!(
        hop_limit_from_control_messages([ControlMessageOwned::Ipv4Ttl(256)].into_iter()),
        None
    );
    assert_eq!(
        hop_limit_from_control_messages([ControlMessageOwned::Ipv6HopLimit(-1)].into_iter()),
        None
    );
}
