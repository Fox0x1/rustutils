use nix::errno::Errno;
use ping::linux::{BackendKind, BackendOpenError, BackendOpenFailure, select_backend};
use std::cell::Cell;
use std::io;

#[test]
fn uses_raw_backend_when_available() {
    let datagram_called = Cell::new(false);

    let selected = select_backend(
        || Ok::<_, BackendOpenFailure>("raw"),
        || {
            datagram_called.set(true);
            Ok("datagram")
        },
    );

    assert!(matches!(selected, Ok(("raw", BackendKind::Raw))));
    assert!(!datagram_called.get());
}

#[test]
fn falls_back_to_ping_socket_when_raw_is_denied() {
    let selected = select_backend(
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::EPERM as i32,
            )))
        },
        || Ok::<_, BackendOpenFailure>("datagram"),
    );

    assert!(matches!(selected, Ok(("datagram", BackendKind::Datagram))));
}

#[test]
fn falls_back_when_raw_protocol_is_unsupported() {
    let selected = select_backend(
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::EPROTONOSUPPORT as i32,
            )))
        },
        || Ok::<_, BackendOpenFailure>("datagram"),
    );

    assert!(matches!(selected, Ok(("datagram", BackendKind::Datagram))));
}

#[test]
fn preserves_both_backend_failures() {
    let selected = select_backend::<&str>(
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::EACCES as i32,
            )))
        },
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::EAFNOSUPPORT as i32,
            )))
        },
    );

    assert!(matches!(
        selected,
        Err(BackendOpenError::Both { raw, datagram })
            if raw.raw_os_error() == Some(Errno::EACCES as i32)
                && datagram.raw_os_error() == Some(Errno::EAFNOSUPPORT as i32)
    ));
}

#[test]
fn does_not_fallback_for_network_errors() {
    let datagram_called = Cell::new(false);

    let selected = select_backend::<&str>(
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::ENETUNREACH as i32,
            )))
        },
        || {
            datagram_called.set(true);
            Ok("datagram")
        },
    );

    assert!(
        matches!(selected, Err(BackendOpenError::Raw(error)) if error.raw_os_error() == Some(Errno::ENETUNREACH as i32))
    );
    assert!(!datagram_called.get());
}

#[test]
fn does_not_fallback_for_resource_errors() {
    let datagram_called = Cell::new(false);

    let selected = select_backend::<&str>(
        || {
            Err(BackendOpenFailure::Socket(io::Error::from_raw_os_error(
                Errno::EMFILE as i32,
            )))
        },
        || {
            datagram_called.set(true);
            Ok("datagram")
        },
    );

    assert!(
        matches!(selected, Err(BackendOpenError::Raw(error)) if error.raw_os_error() == Some(Errno::EMFILE as i32))
    );
    assert!(!datagram_called.get());
}

#[test]
fn does_not_fallback_when_raw_socket_setup_fails() {
    let datagram_called = Cell::new(false);

    let selected = select_backend::<&str>(
        || {
            Err(BackendOpenFailure::Setup(io::Error::from_raw_os_error(
                Errno::EPERM as i32,
            )))
        },
        || {
            datagram_called.set(true);
            Ok("datagram")
        },
    );

    assert!(
        matches!(selected, Err(BackendOpenError::Raw(error)) if error.raw_os_error() == Some(Errno::EPERM as i32))
    );
    assert!(!datagram_called.get());
}
