#![forbid(unsafe_code)]

pub mod config;
pub mod output;
pub mod packet;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(target_os = "linux"))]
compile_error!("the ping system backend is currently implemented for Linux only");
