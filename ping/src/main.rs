#![forbid(unsafe_code)]

use ping::config::{AddressFamily, Config, parse_args};
use ping::linux::IcmpSocket;
use ping::output::{ping_header, reply_line};
use ping::packet::{
    DEFAULT_PAYLOAD_SIZE, build_echo_request_v4, build_echo_request_v6, default_payload,
};
use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct Statistics {
    sent: u64,
    received: u64,
    malformed_packets: u64,
    total_rtt: Duration,
    min_rtt: Option<Duration>,
    max_rtt: Option<Duration>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ping: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let Some(config) = parse_args(std::env::args().skip(1))? else {
        return Ok(());
    };
    let destination = resolve_target(&config)?;
    let start = Instant::now();
    let time_seed = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let requested_identifier = (time_seed as u16) ^ std::process::id() as u16;
    let socket = IcmpSocket::open(destination, requested_identifier, config.ttl)?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal_flag.store(true, Ordering::Relaxed))?;

    let mut statistics = Statistics::default();
    let mut next_send_at = start;

    println!(
        "{}",
        ping_header(
            &config.target,
            socket.destination().ip(),
            DEFAULT_PAYLOAD_SIZE
        )
    );
    while !interrupted.load(Ordering::Relaxed)
        && config.count.is_none_or(|count| statistics.sent < count)
    {
        sleep_until_interruptibly(next_send_at, &interrupted);
        if interrupted.load(Ordering::Relaxed) {
            break;
        }
        let sequence = statistics.sent as u16;
        let payload = default_payload(start.elapsed().as_nanos());
        let packet = build_request(
            destination.ip(),
            socket.source_ip(),
            socket.identifier(),
            sequence,
            &payload,
        )?;
        let sent_at = Instant::now();
        next_send_at = sent_at + config.interval;
        socket.send(&packet)?;
        statistics.sent += 1;

        let result =
            socket.receive_echo_reply(sequence, &payload, sent_at, config.timeout, &interrupted)?;
        statistics.malformed_packets += result.malformed_packets;

        if let Some(reply) = result.reply {
            statistics.received += 1;
            statistics.total_rtt += result.elapsed;
            statistics.min_rtt = Some(
                statistics
                    .min_rtt
                    .map_or(result.elapsed, |current| current.min(result.elapsed)),
            );
            statistics.max_rtt = Some(
                statistics
                    .max_rtt
                    .map_or(result.elapsed, |current| current.max(result.elapsed)),
            );
            println!(
                "{}",
                reply_line(
                    destination.ip(),
                    reply.sequence,
                    reply.hop_limit,
                    result.elapsed,
                    packet.len(),
                )
            );
        } else if !interrupted.load(Ordering::Relaxed) {
            println!("Request timeout for icmp_seq {sequence}");
        }
    }

    print_statistics(destination.ip(), &statistics);
    Ok(())
}

fn build_request(
    destination: IpAddr,
    source: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>, io::Error> {
    match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Ok(build_echo_request_v4(identifier, sequence, payload)),
        (IpAddr::V6(source), IpAddr::V6(destination)) => Ok(build_echo_request_v6(
            source,
            destination,
            identifier,
            sequence,
            payload,
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and destination address families differ",
        )),
    }
}

fn resolve_target(config: &Config) -> Result<SocketAddr, Box<dyn Error>> {
    let mut addresses = (config.target.as_str(), 0).to_socket_addrs()?;
    addresses
        .find(|address| match config.family {
            Some(AddressFamily::Ipv4) => address.is_ipv4(),
            Some(AddressFamily::Ipv6) => address.is_ipv6(),
            None => true,
        })
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no matching address found").into()
        })
}

fn print_statistics(target: IpAddr, statistics: &Statistics) {
    let packet_loss = if statistics.sent == 0 {
        0.0
    } else {
        (statistics.sent - statistics.received) as f64 * 100.0 / statistics.sent as f64
    };
    println!(
        "\n--- {target} ping statistics ---\n{} packets transmitted, {} received, {:.1}% packet loss",
        statistics.sent, statistics.received, packet_loss
    );
    if let (Some(min), Some(max)) = (statistics.min_rtt, statistics.max_rtt) {
        let average =
            statistics.total_rtt.as_secs_f64() * 1000.0 / statistics.received.max(1) as f64;
        println!(
            "rtt min/avg/max = {:.3}/{average:.3}/{:.3} ms",
            min.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0
        );
    }
    if statistics.malformed_packets > 0 {
        println!("{} malformed packets ignored", statistics.malformed_packets);
    }
}

fn sleep_until_interruptibly(deadline: Instant, interrupted: &AtomicBool) {
    while !interrupted.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}
