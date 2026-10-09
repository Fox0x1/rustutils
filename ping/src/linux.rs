use crate::packet::{
    EchoReply, parse_echo_reply_v4, parse_echo_reply_v4_message, parse_echo_reply_v6,
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, ControlMessageOwned, SockFlag, SockProtocol, SockType, SockaddrIn, SockaddrIn6,
    SockaddrStorage, bind, connect, getsockname, recvmsg, send, setsockopt, socket, sockopt,
};
use std::error::Error;
use std::fmt;
use std::io;
use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Raw,
    Datagram,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopLimitOption {
    Ipv4Ttl,
    Ipv6UnicastHops,
}

pub fn hop_limit_option(destination: IpAddr) -> HopLimitOption {
    match destination {
        IpAddr::V4(_) => HopLimitOption::Ipv4Ttl,
        IpAddr::V6(_) => HopLimitOption::Ipv6UnicastHops,
    }
}

pub fn hop_limit_from_control_messages(
    mut messages: impl Iterator<Item = ControlMessageOwned>,
) -> Option<u8> {
    messages.find_map(|message| {
        let value = match message {
            ControlMessageOwned::Ipv4Ttl(value) | ControlMessageOwned::Ipv6HopLimit(value) => value,
            _ => return None,
        };
        u8::try_from(value).ok()
    })
}

pub fn set_hop_limit<F: AsFd>(
    socket: &F,
    destination: IpAddr,
    ttl: u8,
) -> io::Result<HopLimitOption> {
    let value = i32::from(ttl);
    let option = hop_limit_option(destination);
    let result = match option {
        HopLimitOption::Ipv4Ttl => setsockopt(socket, sockopt::Ipv4Ttl, &value),
        HopLimitOption::Ipv6UnicastHops => setsockopt(socket, sockopt::Ipv6Ttl, &value),
    };
    result.map_err(errno_to_io)?;
    Ok(option)
}

#[derive(Debug)]
pub enum BackendOpenError {
    Raw(io::Error),
    Both { raw: io::Error, datagram: io::Error },
}

pub enum BackendOpenFailure {
    Socket(io::Error),
    Setup(io::Error),
}

impl BackendOpenFailure {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::Socket(error) | Self::Setup(error) => error,
        }
    }
}

impl fmt::Display for BackendOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw(error) => write!(formatter, "SOCK_RAW backend failed: {error}"),
            Self::Both { raw, datagram } => write!(
                formatter,
                "SOCK_RAW backend failed: {raw}; ICMP ping socket backend failed: {datagram}"
            ),
        }
    }
}

impl Error for BackendOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Raw(error) => Some(error),
            Self::Both { raw, .. } => Some(raw),
        }
    }
}

pub fn select_backend<T>(
    raw: impl FnOnce() -> Result<T, BackendOpenFailure>,
    datagram: impl FnOnce() -> Result<T, BackendOpenFailure>,
) -> Result<(T, BackendKind), BackendOpenError> {
    match raw() {
        Ok(backend) => Ok((backend, BackendKind::Raw)),
        Err(BackendOpenFailure::Socket(error)) if should_try_datagram(&error) => match datagram() {
            Ok(backend) => Ok((backend, BackendKind::Datagram)),
            Err(datagram_error) => Err(BackendOpenError::Both {
                raw: error,
                datagram: datagram_error.into_io_error(),
            }),
        },
        Err(error) => Err(BackendOpenError::Raw(error.into_io_error())),
    }
}

fn should_try_datagram(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::PermissionDenied {
        return true;
    }

    matches!(
        error.raw_os_error(),
        Some(code)
            if code == Errno::EAFNOSUPPORT as i32
                || code == Errno::EPROTONOSUPPORT as i32
                || code == Errno::ESOCKTNOSUPPORT as i32
                || code == Errno::EOPNOTSUPP as i32
                || code == Errno::ENOPROTOOPT as i32
                || code == Errno::ENOSYS as i32
    )
}

pub struct IcmpSocket {
    fd: OwnedFd,
    backend: BackendKind,
    destination: SocketAddr,
    source: SocketAddr,
    identifier: u16,
}

pub struct ReceiveResult {
    pub reply: Option<EchoReply>,
    pub elapsed: Duration,
    pub malformed_packets: u64,
}

impl IcmpSocket {
    pub fn open(
        destination: SocketAddr,
        requested_identifier: u16,
        ttl: Option<u8>,
    ) -> Result<Self, BackendOpenError> {
        select_backend(
            || Self::open_with(destination, requested_identifier, ttl, BackendKind::Raw),
            || {
                Self::open_with(
                    destination,
                    requested_identifier,
                    ttl,
                    BackendKind::Datagram,
                )
            },
        )
        .map(|(socket, _)| socket)
    }

    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let written = send(
            self.fd.as_raw_fd(),
            packet,
            nix::sys::socket::MsgFlags::empty(),
        )
        .map_err(errno_to_io)?;
        if written != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "socket sent a partial ICMP packet",
            ));
        }
        Ok(())
    }

    pub fn source_ip(&self) -> IpAddr {
        self.source.ip()
    }

    pub fn identifier(&self) -> u16 {
        self.identifier
    }

    pub fn backend(&self) -> BackendKind {
        self.backend
    }

    pub fn receive_echo_reply(
        &self,
        sequence: u16,
        payload: &[u8],
        sent_at: Instant,
        timeout: Duration,
        interrupted: &AtomicBool,
    ) -> io::Result<ReceiveResult> {
        let deadline = sent_at + timeout;
        let mut buffer = [0u8; 65_535];
        let mut malformed_packets = 0;

        while !interrupted.load(Ordering::Relaxed) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let mut descriptors = [PollFd::new(self.fd.as_fd(), PollFlags::POLLIN)];
            let poll_timeout = poll_timeout(remaining.min(Duration::from_millis(100)))?;
            let ready = match poll(&mut descriptors, poll_timeout) {
                Ok(ready) => ready,
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(errno_to_io(error)),
            };
            if ready == 0 {
                continue;
            }

            let mut control = nix::cmsg_space!(i32, i32);
            let (length, address, received_hop_limit) = {
                let mut iov = [IoSliceMut::new(&mut buffer)];
                let message = match recvmsg::<SockaddrStorage>(
                    self.fd.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    nix::sys::socket::MsgFlags::empty(),
                ) {
                    Ok(message) => message,
                    Err(Errno::EINTR) => continue,
                    Err(error) => return Err(errno_to_io(error)),
                };
                let hop_limit =
                    hop_limit_from_control_messages(message.cmsgs().map_err(errno_to_io)?);
                (message.bytes, message.address, hop_limit)
            };
            let received_at = Instant::now();
            let peer = socket_address_ip(address)?;

            let parsed = self.parse_received_packet(&buffer[..length], peer, sequence, payload);
            match parsed {
                Ok(Some(mut reply)) => {
                    reply.hop_limit = received_hop_limit.or(reply.hop_limit);
                    return Ok(ReceiveResult {
                        reply: Some(reply),
                        elapsed: received_at.duration_since(sent_at),
                        malformed_packets,
                    });
                }
                Ok(None) => {}
                Err(_) => malformed_packets += 1,
            }
        }

        Ok(ReceiveResult {
            reply: None,
            elapsed: sent_at.elapsed(),
            malformed_packets,
        })
    }

    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    fn open_with(
        destination: SocketAddr,
        requested_identifier: u16,
        ttl: Option<u8>,
        backend: BackendKind,
    ) -> Result<Self, BackendOpenFailure> {
        let (family, protocol) = match destination {
            SocketAddr::V4(_) => (AddressFamily::Inet, SockProtocol::Icmp),
            SocketAddr::V6(_) => (AddressFamily::Inet6, SockProtocol::IcmpV6),
        };
        let socket_type = match backend {
            BackendKind::Raw => SockType::Raw,
            BackendKind::Datagram => SockType::Datagram,
        };
        let fd = socket(family, socket_type, SockFlag::empty(), protocol)
            .map_err(errno_to_io)
            .map_err(BackendOpenFailure::Socket)?;
        match destination {
            SocketAddr::V4(_) => {
                setsockopt(&fd, sockopt::Ipv4RecvTtl, &true)
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
            }
            SocketAddr::V6(_) => {
                setsockopt(&fd, sockopt::Ipv6RecvHopLimit, &true)
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
            }
        }
        if let Some(ttl) = ttl {
            set_hop_limit(&fd, destination.ip(), ttl).map_err(BackendOpenFailure::Setup)?;
        }
        if backend == BackendKind::Datagram {
            match destination {
                SocketAddr::V4(_) => {
                    let local =
                        SockaddrIn::from(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
                    bind(fd.as_raw_fd(), &local)
                        .map_err(errno_to_io)
                        .map_err(BackendOpenFailure::Setup)?;
                }
                SocketAddr::V6(_) => {
                    let local = SockaddrIn6::from(SocketAddrV6::new(
                        std::net::Ipv6Addr::UNSPECIFIED,
                        0,
                        0,
                        0,
                    ));
                    bind(fd.as_raw_fd(), &local)
                        .map_err(errno_to_io)
                        .map_err(BackendOpenFailure::Setup)?;
                }
            }
        }
        match destination {
            SocketAddr::V4(address) => {
                connect(fd.as_raw_fd(), &SockaddrIn::from(address))
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
            }
            SocketAddr::V6(address) => {
                connect(fd.as_raw_fd(), &SockaddrIn6::from(address))
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
            }
        }

        let (source, identifier) = match destination {
            SocketAddr::V4(_) => {
                let source: SockaddrIn = getsockname(fd.as_raw_fd())
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
                let identifier = if backend == BackendKind::Datagram {
                    source.port()
                } else {
                    requested_identifier
                };
                (
                    SocketAddr::V4(SocketAddrV4::new(source.ip(), source.port())),
                    identifier,
                )
            }
            SocketAddr::V6(_) => {
                let source: SockaddrIn6 = getsockname(fd.as_raw_fd())
                    .map_err(errno_to_io)
                    .map_err(BackendOpenFailure::Setup)?;
                let identifier = if backend == BackendKind::Datagram {
                    source.port()
                } else {
                    requested_identifier
                };
                (
                    SocketAddr::V6(SocketAddrV6::new(
                        source.ip(),
                        source.port(),
                        source.flowinfo(),
                        source.scope_id(),
                    )),
                    identifier,
                )
            }
        };

        Ok(Self {
            fd,
            backend,
            destination,
            source,
            identifier,
        })
    }

    fn parse_received_packet(
        &self,
        packet: &[u8],
        peer: IpAddr,
        sequence: u16,
        payload: &[u8],
    ) -> Result<Option<EchoReply>, crate::packet::PacketError> {
        match (self.backend, self.source, self.destination, peer) {
            (
                BackendKind::Raw,
                SocketAddr::V4(source),
                SocketAddr::V4(destination),
                IpAddr::V4(_),
            ) => parse_echo_reply_v4(
                packet,
                *destination.ip(),
                *source.ip(),
                self.identifier,
                sequence,
                payload,
            ),
            (
                BackendKind::Datagram,
                SocketAddr::V4(_),
                SocketAddr::V4(destination),
                IpAddr::V4(peer),
            ) => {
                if peer != *destination.ip() {
                    return Ok(None);
                }
                parse_echo_reply_v4_message(packet, self.identifier, sequence, payload)
            }
            (_, SocketAddr::V6(source), SocketAddr::V6(destination), IpAddr::V6(peer)) => {
                if peer != *destination.ip() {
                    return Ok(None);
                }
                parse_echo_reply_v6(
                    packet,
                    peer,
                    *source.ip(),
                    self.identifier,
                    sequence,
                    payload,
                )
            }
            _ => Ok(None),
        }
    }
}

fn socket_address_ip(address: Option<SockaddrStorage>) -> io::Result<IpAddr> {
    let address = address.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "received packet has no source address",
        )
    })?;
    if let Some(address) = address.as_sockaddr_in() {
        return Ok(IpAddr::V4(address.ip()));
    }
    if let Some(address) = address.as_sockaddr_in6() {
        return Ok(IpAddr::V6(address.ip()));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "received packet has an unsupported source address",
    ))
}

fn poll_timeout(remaining: Duration) -> io::Result<PollTimeout> {
    PollTimeout::try_from(remaining).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid receive timeout: {error}"),
        )
    })
}

fn errno_to_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
