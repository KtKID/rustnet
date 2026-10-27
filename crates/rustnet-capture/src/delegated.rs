//! Darwin BPF descriptor handoff. The privileged helper exits before sampling;
//! the ordinary collector owns the descriptor, packet reads and every file.

use super::{CaptureConfig, CaptureStats, CapturedPacket, PacketReader};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub socket_path: String,
    pub nonce: String,
    pub interface: Option<String>,
    pub uid: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    nonce: String,
    device: String,
    linktype: i32,
}

static PREPARED: Mutex<Option<(BpfReader, String, i32)>> = Mutex::new(None);

#[repr(C)]
#[derive(Default)]
struct Record {
    seconds: i64,
    microseconds: i64,
    offset: u32,
    captured: u32,
    original: u32,
    next: u32,
}
unsafe extern "C" {
    fn pcap_get_selectable_fd(capture: *mut std::ffi::c_void) -> i32;
    fn rustnet_bpf_dimensions(fd: i32, length: *mut u32, linktype: *mut u32) -> i32;
    fn rustnet_bpf_record(buffer: *const u8, length: u32, offset: u32, record: *mut Record) -> i32;
    fn rustnet_bpf_stats(fd: i32, received: *mut u32, dropped: *mut u32) -> i32;
}

pub fn helper(request: Request) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "capture helper requires administrator authorization"
    );
    let mut stream = UnixStream::connect(&request.socket_path)?;
    let mut uid = 0;
    let mut gid = 0;
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0
            && uid == request.uid,
        "capture recipient identity mismatch"
    );
    let (capture, device, linktype) = super::setup_packet_capture(CaptureConfig {
        interface: request.interface,
        ..CaptureConfig::default()
    })?;
    let fd = unsafe { pcap_get_selectable_fd(capture.as_ptr().cast()) };
    ensure!(fd >= 0, "capture has no transferable BPF descriptor");
    let metadata = serde_json::to_vec(&Metadata {
        nonce: request.nonce,
        device,
        linktype,
    })?;
    let mut payload = (metadata.len() as u32).to_be_bytes().to_vec();
    payload.extend(metadata);
    let mut control = [0_usize; 8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) };
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32);
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
    }
    let count = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    ensure!(
        count >= 0,
        "send BPF descriptor: {}",
        io::Error::last_os_error()
    );
    if (count as usize) < payload.len() {
        stream.write_all(&payload[count as usize..])?;
    }
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut ack = [0_u8; 2];
    stream.read_exact(&mut ack)?;
    ensure!(&ack == b"OK", "capture receiver rejected handoff");
    // The receiver owns the duplicated BPF descriptor. Avoid libpcap's explicit
    // interface cleanup here; kernel descriptor lifetime now follows the receiver.
    std::mem::forget(capture);
    Ok(())
}

pub fn receive(mut stream: UnixStream, nonce: &str) -> Result<()> {
    let mut uid = 0;
    let mut gid = 0;
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == 0,
        "capture sender requires administrator identity"
    );
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut payload = vec![0_u8; 4096];
    let mut control = [0_usize; 8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as u32;
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    ensure!(
        count >= 4,
        "capture helper did not send a descriptor: {}",
        io::Error::last_os_error()
    );
    let header = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    ensure!(
        !header.is_null() && msg.msg_flags & libc::MSG_CTRUNC == 0,
        "capture descriptor missing/truncated"
    );
    ensure!(
        unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len == libc::CMSG_LEN(std::mem::size_of::<i32>() as u32)
        },
        "invalid descriptor message"
    );
    let fd = unsafe {
        OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(header).cast::<i32>(),
        ))
    };
    payload.truncate(count as usize);
    let length = u32::from_be_bytes(payload[..4].try_into()?) as usize;
    ensure!(
        length > 0 && length < 4092,
        "capture metadata length invalid"
    );
    if payload.len() < length + 4 {
        let previous = payload.len();
        payload.resize(length + 4, 0);
        stream.read_exact(&mut payload[previous..])?;
    }
    ensure!(payload.len() == length + 4, "extra capture metadata");
    let metadata: Metadata = serde_json::from_slice(&payload[4..])?;
    ensure!(metadata.nonce == nonce, "capture startup token mismatch");
    let mut buffer_size = 0;
    let mut linktype = 0;
    ensure!(
        unsafe { rustnet_bpf_dimensions(fd.as_raw_fd(), &mut buffer_size, &mut linktype) } == 0,
        "received descriptor is not a BPF capture"
    );
    ensure!(
        buffer_size > 0 && buffer_size <= 32 * 1024 * 1024 && linktype as i32 == metadata.linktype,
        "capture descriptor metadata mismatch"
    );
    let reader = BpfReader {
        file: File::from(fd),
        buffer: vec![0_u8; buffer_size as usize],
        length: 0,
        position: 0,
    };
    let mut slot = PREPARED
        .lock()
        .map_err(|_| anyhow::anyhow!("capture handoff lock poisoned"))?;
    ensure!(slot.is_none(), "capture descriptor already installed");
    *slot = Some((reader, metadata.device, metadata.linktype));
    stream.write_all(b"OK")?;
    Ok(())
}

pub fn is_prepared() -> bool {
    PREPARED.lock().is_ok_and(|slot| slot.is_some())
}
pub(super) fn take_reader() -> Result<Option<(PacketReader, String, i32)>> {
    Ok(PREPARED
        .lock()
        .map_err(|_| anyhow::anyhow!("capture handoff lock poisoned"))?
        .take()
        .map(|(reader, device, linktype)| {
            if linktype != 149 {
                let _ = super::PKTAP_DEGRADATION_REASON
                    .set(super::PktapUnavailable::InterfaceSpecified);
            }
            (
                PacketReader {
                    capture: None,
                    idle_wait: None,
                    delegated: Some(reader),
                },
                device,
                linktype,
            )
        }))
}

pub(super) struct BpfReader {
    file: File,
    buffer: Vec<u8>,
    length: usize,
    position: usize,
}
impl BpfReader {
    pub fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        if self.position >= self.length {
            match self.file.read(&mut self.buffer) {
                Ok(0) => bail!("BPF descriptor closed"),
                Ok(size) => {
                    self.length = size;
                    self.position = 0;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    let mut descriptor = libc::pollfd {
                        fd: self.file.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let result = unsafe {
                        libc::poll(
                            &mut descriptor,
                            1,
                            super::IDLE_POLL_INTERVAL.as_millis() as i32,
                        )
                    };
                    if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                    ensure!(
                        descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                        "BPF descriptor became unavailable"
                    );
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let mut record = Record::default();
        ensure!(
            unsafe {
                rustnet_bpf_record(
                    self.buffer.as_ptr(),
                    self.length as u32,
                    self.position as u32,
                    &mut record,
                )
            } == 1,
            "invalid BPF packet boundary"
        );
        self.position = record.next as usize;
        Ok(Some(CapturedPacket {
            data: self.buffer[record.offset as usize..(record.offset + record.captured) as usize]
                .to_vec(),
            timestamp: super::timeval_to_system_time(record.seconds, record.microseconds),
            original_len: record.original,
        }))
    }
    pub fn stats(&mut self) -> Result<CaptureStats> {
        let mut received = 0;
        let mut dropped = 0;
        ensure!(
            unsafe { rustnet_bpf_stats(self.file.as_raw_fd(), &mut received, &mut dropped) } == 0,
            "BPF statistics failed"
        );
        Ok(CaptureStats {
            received,
            dropped,
            if_dropped: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_bpf_reader_checks_packet_and_buffer_boundaries() {
        let mut bytes = Vec::new();
        bytes.extend(123_i32.to_ne_bytes());
        bytes.extend(456_i32.to_ne_bytes());
        bytes.extend(4_u32.to_ne_bytes());
        bytes.extend(8_u32.to_ne_bytes());
        bytes.extend(20_u16.to_ne_bytes());
        bytes.extend([0, 0]);
        bytes.extend([1, 2, 3, 4]);
        let mut record = Record::default();
        assert_eq!(
            unsafe { rustnet_bpf_record(bytes.as_ptr(), bytes.len() as u32, 0, &mut record) },
            1
        );
        assert_eq!(
            (
                record.seconds,
                record.microseconds,
                record.offset,
                record.captured,
                record.original,
                record.next
            ),
            (123, 456, 20, 4, 8, 24)
        );
        assert!(unsafe { rustnet_bpf_record(bytes.as_ptr(), 19, 0, &mut record) } < 0);
        bytes[8..12].copy_from_slice(&100_u32.to_ne_bytes());
        assert!(
            unsafe { rustnet_bpf_record(bytes.as_ptr(), bytes.len() as u32, 0, &mut record) } < 0
        );
    }
}
