use std::error::Error;
use std::time::Duration;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_MILLISECONDS: u64 = 86_400_000;

pub struct Config {
    pub target: String,
    pub family: Option<AddressFamily>,
    pub count: Option<u64>,
    pub interval: Duration,
    pub timeout: Duration,
    pub ttl: Option<u8>,
}

#[derive(Clone, Copy)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

pub fn parse_args(
    arguments: impl Iterator<Item = String>,
) -> Result<Option<Config>, Box<dyn Error>> {
    let mut arguments = arguments;
    let mut config = Config {
        target: String::new(),
        family: None,
        count: None,
        interval: DEFAULT_INTERVAL,
        timeout: DEFAULT_TIMEOUT,
        ttl: None,
    };

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            "-4" | "--ipv4" => config.family = Some(AddressFamily::Ipv4),
            "-6" | "--ipv6" => config.family = Some(AddressFamily::Ipv6),
            "-c" | "--count" => {
                let count = next_value(&mut arguments, &argument)?.parse::<u64>()?;
                if count == 0 {
                    return Err("count must be greater than zero".into());
                }
                config.count = Some(count);
            }
            "-i" | "--interval" => {
                config.interval = parse_duration(&next_value(&mut arguments, &argument)?)?;
            }
            "-W" | "--timeout" => {
                config.timeout = parse_duration(&next_value(&mut arguments, &argument)?)?;
            }
            "-t" | "--ttl" | "--hop-limit" => {
                config.ttl = Some(parse_ttl(&next_value(&mut arguments, &argument)?)?);
            }
            option if option.starts_with('-') => {
                return Err(format!("unknown option: {option}").into());
            }
            target if config.target.is_empty() => config.target = target.to_owned(),
            target => return Err(format!("unexpected argument: {target}").into()),
        }
    }

    if config.target.is_empty() {
        print_usage();
        return Err("destination is required".into());
    }

    Ok(Some(config))
}

fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("missing value for {option}").into())
}

fn parse_duration(value: &str) -> Result<Duration, Box<dyn Error>> {
    let milliseconds = value.parse::<u64>()?;
    if milliseconds == 0 || milliseconds > MAX_MILLISECONDS {
        return Err(format!("duration must be between 1 and {MAX_MILLISECONDS} ms").into());
    }
    Ok(Duration::from_millis(milliseconds))
}

fn parse_ttl(value: &str) -> Result<u8, Box<dyn Error>> {
    let ttl = value.parse::<u8>()?;
    if ttl == 0 {
        return Err("TTL or hop limit must be between 1 and 255".into());
    }
    Ok(ttl)
}

pub fn print_usage() {
    println!(
        "Usage: ping [-4 | -6] [-c count] [-i interval_ms] [-W timeout_ms] [-t ttl] destination\n\n\
         Options:\n\
         -4, --ipv4          use IPv4\n\
         -6, --ipv6          use IPv6\n\
         -c, --count N       stop after N requests (default: until Ctrl+C)\n\
         -i, --interval MS   delay between requests (default: 1000 ms)\n\
         -W, --timeout MS    response timeout (default: 1000 ms)\n\
         -t, --ttl N         set IPv4 TTL or IPv6 Hop Limit (1-255)\n\
         --hop-limit N       alias for --ttl"
    );
}
