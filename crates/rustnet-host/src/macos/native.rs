//! In-process libproc inventory shared by attribution and listener collection.

use super::process::resolve_process_details;
use crate::{ConnectionKey, HostSocket, HostSocketState, HostTcpState, SocketOwner, SocketScan};
use anyhow::{Result, bail};
use rustnet_core::network::types::Protocol;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
#[derive(Default)]
struct NativeSocket {
    family: i32,
    protocol: i32,
    state: i32,
    local_port: u16,
    remote_port: u16,
    local_address: [u8; 16],
    remote_address: [u8; 16],
    identity: u64,
}
unsafe extern "C" {
    fn rustnet_socket_info(pid: i32, fd: i32, output: *mut NativeSocket) -> i32;
}

pub(super) fn scan(cancelled: Option<&AtomicBool>) -> Result<SocketScan> {
    check_cancelled(cancelled)?;
    let mut result = SocketScan {
        complete: true,
        ..SocketScan::default()
    };
    // SAFETY: null requests the required list capacity; the next call owns a sized buffer.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        bail!(
            "proc_listallpids failed: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut pids = vec![0_i32; count as usize + 128];
    // SAFETY: libproc receives the live allocation and its byte length.
    let used = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr().cast(),
            (pids.len() * size_of::<i32>()).try_into()?,
        )
    };
    if used <= 0 || used as usize >= pids.len() {
        bail!("process inventory changed beyond its buffer");
    }
    pids.truncate(used as usize);
    // SAFETY: geteuid takes no pointers.
    let uid = unsafe { libc::geteuid() };
    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        check_cancelled(cancelled)?;
        let Some(details) = resolve_process_details(pid as u32) else {
            continue;
        };
        if uid != 0 && details.uid != uid {
            continue;
        }
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            128
        ];
        let mut filled = false;
        for _ in 0..8 {
            let bytes: i32 = (fds.len() * size_of::<libc::proc_fdinfo>()).try_into()?;
            // SAFETY: the allocation matches PROC_PIDLISTFDS's documented structure.
            let returned = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    bytes,
                )
            };
            if returned <= 0 {
                let error = std::io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
                    result.complete = false;
                }
                fds.clear();
                filled = true;
                break;
            }
            if returned < bytes {
                fds.truncate(returned as usize / size_of::<libc::proc_fdinfo>());
                filled = true;
                break;
            }
            fds.resize(
                fds.len() * 2,
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                },
            );
        }
        if !filled {
            result.complete = false;
            continue;
        }
        let owner = SocketOwner::new(pid as u32, details.name.clone(), Some(details.uid));
        for fd in fds
            .into_iter()
            .filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
        {
            check_cancelled(cancelled)?;
            let mut socket = NativeSocket::default();
            // SAFETY: the C wrapper initializes exactly the repr(C) output on success.
            let status = unsafe { rustnet_socket_info(pid, fd.proc_fd, &mut socket) };
            if status < 0 {
                if !matches!(
                    -status,
                    libc::EBADF | libc::ESRCH | libc::ENOENT | libc::ENOTSOCK
                ) {
                    result.complete = false;
                }
                continue;
            }
            if status == 0 || socket.local_port == 0 {
                continue;
            }
            let protocol = if socket.protocol == libc::IPPROTO_TCP {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            let address = |bytes: [u8; 16]| -> Result<IpAddr> {
                Ok(if socket.family == libc::AF_INET {
                    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
                } else if socket.family == libc::AF_INET6 {
                    IpAddr::V6(Ipv6Addr::from(bytes))
                } else {
                    bail!("unsupported socket address family")
                })
            };
            let local = SocketAddr::new(address(socket.local_address)?, socket.local_port);
            let remote = SocketAddr::new(address(socket.remote_address)?, socket.remote_port);
            let state = if protocol == Protocol::Tcp {
                const STATES: [&str; 12] = [
                    "CLOSED",
                    "LISTEN",
                    "SYN_SENT",
                    "SYN_RECEIVED",
                    "ESTABLISHED",
                    "CLOSE_WAIT",
                    "FIN_WAIT_1",
                    "CLOSING",
                    "LAST_ACK",
                    "FIN_WAIT_2",
                    "TIME_WAIT",
                    "RESERVED",
                ];
                HostSocketState::Tcp(HostTcpState::parse_name(
                    STATES
                        .get(socket.state as usize)
                        .copied()
                        .unwrap_or("UNKNOWN"),
                ))
            } else {
                HostSocketState::UdpBound
            };
            result.lookup.insert(
                ConnectionKey {
                    protocol,
                    local_addr: local,
                    remote_addr: remote,
                },
                owner.clone(),
            );
            result.sockets.push(HostSocket {
                protocol,
                local_addr: local,
                remote_addr: (socket.remote_port != 0).then_some(remote),
                state,
                owner: Some(owner.clone()),
                native_id: Some(socket.identity),
            });
        }
    }
    Ok(result)
}

fn check_cancelled(cancelled: Option<&AtomicBool>) -> Result<()> {
    if cancelled.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(
            std::io::Error::new(std::io::ErrorKind::Interrupted, "socket scan cancelled").into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_inventory_observes_real_ipv4_ipv6_and_udp() {
        let tcp4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp6 = std::net::TcpListener::bind("[::1]:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inventory = scan(None).unwrap();
        assert!(inventory.complete, "native own-user scan must be complete");
        for endpoint in [
            tcp4.local_addr().unwrap(),
            tcp6.local_addr().unwrap(),
            udp.local_addr().unwrap(),
        ] {
            assert!(
                inventory.sockets.iter().any(|s| s.local_addr == endpoint
                    && s.owner
                        .as_ref()
                        .is_some_and(|p| p.pid == std::process::id())),
                "missing {endpoint}"
            );
        }
    }
}
