use ping::config::{AddressFamily, parse_args};
use std::error::Error;

fn parse(arguments: &[&str]) -> Result<Option<ping::config::Config>, Box<dyn Error>> {
    parse_args(arguments.iter().map(|argument| (*argument).to_owned()))
}

#[test]
fn parses_ttl_and_ipv4_selection() -> Result<(), Box<dyn Error>> {
    let config = parse(&["-4", "--ttl", "37", "127.0.0.1"])?.ok_or("expected config")?;

    assert_eq!(config.ttl, Some(37));
    assert!(matches!(config.family, Some(AddressFamily::Ipv4)));
    Ok(())
}

#[test]
fn parses_hop_limit_alias_for_ipv6() -> Result<(), Box<dyn Error>> {
    let config = parse(&["-6", "--hop-limit", "64", "::1"])?.ok_or("expected config")?;

    assert_eq!(config.ttl, Some(64));
    assert!(matches!(config.family, Some(AddressFamily::Ipv6)));
    Ok(())
}

#[test]
fn accepts_short_ttl_option_and_maximum_value() -> Result<(), Box<dyn Error>> {
    let config = parse(&["-t", "255", "localhost"])?.ok_or("expected config")?;

    assert_eq!(config.ttl, Some(255));
    Ok(())
}

#[test]
fn rejects_invalid_ttl_values() {
    for value in ["0", "256", "not-a-number"] {
        assert!(parse(&["--ttl", value, "localhost"]).is_err());
    }
}

#[test]
fn ttl_is_unset_by_default() -> Result<(), Box<dyn Error>> {
    let config = parse(&["localhost"])?.ok_or("expected config")?;

    assert_eq!(config.ttl, None);
    Ok(())
}
