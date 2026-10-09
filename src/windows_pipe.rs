//! Local named-pipe transport of the maintenance service.
//!
//! The server keeps several overlapped instances of its pipe listening at all times, so the name
//! never becomes free while the service runs, and one client that connects without writing can
//! hold only its own instance until the read timeout. The first instance is created with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE`: if another process already owns the name, the service refuses
//! to start instead of joining that process's pipe.
//!
//! A client writes nothing before it has checked that the server end belongs to the process the
//! Service Control Manager reports for the maintenance service.

use std::{
    cell::Cell,
    collections::VecDeque,
    fs::File,
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};

use windows::{
    Win32::{
        Foundation::{
            ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IMPERSONATION,
            SECURITY_SQOS_PRESENT, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeServerProcessId, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_MESSAGE, PIPE_WAIT, WaitNamedPipeW,
            },
            Threading::WaitForMultipleObjects,
        },
    },
    core::{HRESULT, PCWSTR},
};

use super::{
    KernelHandle, LocalSecurityDescriptor, PIPE_CLIENT_ACCESS_MASK, create_event, open_absolute,
    raw_handle, wait_for_pipe_ready_with, wide_null,
};
use crate::{ErrorCode, MAX_IPC_MESSAGE_BYTES, MaintenanceError, Result};

/// Concurrent pipe instances of the service. Each one serves a single connection at a time.
pub(super) const SERVICE_PIPE_INSTANCES: u32 = 4;
/// A connected client must send its request within this time.
pub(super) const PIPE_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A client must accept its response within this time.
pub(super) const PIPE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

fn is_win32(error: &windows::core::Error, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(code.0)
}

fn pipe_error(
    code: ErrorCode,
    detail: &'static str,
    error: &windows::core::Error,
) -> MaintenanceError {
    // HRESULT_FROM_WIN32 keeps the Win32 code in the low 16 bits.
    let status = u32::from_ne_bytes(error.code().0.to_ne_bytes()) & 0xffff;
    MaintenanceError::with_platform_status(code, detail, status)
}

fn milliseconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis())
        .unwrap_or(u32::MAX - 1)
        .min(u32::MAX - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// A ConnectNamedPipe operation is pending.
    Listening,
    /// A client is connected and a ReadFile operation is pending until the deadline.
    Reading(Instant),
    /// A request was handed to the caller; no I/O is pending until it responds.
    Held,
}

struct Instance {
    pipe: KernelHandle,
    event: KernelHandle,
    // Boxed so the kernel's pointers stay valid when the instance moves.
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u8]>,
    phase: Phase,
}

/// What a read or connect completion produced.
enum Progress {
    Pending,
    Request(Result<Vec<u8>>),
}

impl Instance {
    fn create(name: &[u16], first: bool, instances: u32) -> Result<Self> {
        let mut descriptor = LocalSecurityDescriptor::parse(super::PIPE_DACL_SDDL)?;
        let attributes = descriptor.attributes();
        let first_flag = if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            Default::default()
        };
        // SAFETY: the name is NUL-terminated, the security attributes and descriptor outlive the
        // synchronous call, and all buffer and count values are bounded constants.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first_flag,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                instances,
                u32::try_from(MAX_IPC_MESSAGE_BYTES).unwrap_or(u32::MAX),
                u32::try_from(MAX_IPC_MESSAGE_BYTES).unwrap_or(u32::MAX),
                30_000,
                Some(ptr::from_ref(&attributes)),
            )
        };
        let pipe = KernelHandle::new(
            handle,
            ErrorCode::TransactionIo,
            if first {
                "local maintenance pipe name is already in use"
            } else {
                "local maintenance pipe instance could not be created"
            },
        )?;
        Ok(Self {
            pipe,
            event: create_event(true, false)?,
            overlapped: Box::default(),
            buffer: vec![0_u8; MAX_IPC_MESSAGE_BYTES].into_boxed_slice(),
            phase: Phase::Held,
        })
    }

    fn reset_overlapped(&mut self) {
        *self.overlapped = OVERLAPPED {
            hEvent: self.event.raw(),
            ..Default::default()
        };
    }

    const fn has_pending_io(&self) -> bool {
        matches!(self.phase, Phase::Listening | Phase::Reading(_))
    }

    /// Cancels the pending operation and waits until the kernel no longer uses the buffers.
    fn cancel_pending(&mut self) {
        if self.has_pending_io() {
            // SAFETY: the OVERLAPPED belongs to this instance's single pending operation; waiting
            // for its result drains completion or cancellation before the storage is reused.
            unsafe {
                let _ = CancelIoEx(self.pipe.raw(), Some(&*self.overlapped));
                let mut transferred = 0_u32;
                let _ =
                    GetOverlappedResult(self.pipe.raw(), &*self.overlapped, &mut transferred, true);
            }
            self.phase = Phase::Held;
        }
    }

    /// Drops the current client, if any, and starts listening for the next one.
    fn listen(&mut self, read_timeout: Duration) -> Result<Progress> {
        self.cancel_pending();
        // SAFETY: the pipe handle is a live server instance; disconnecting an idle instance only
        // fails harmlessly.
        let _ = unsafe { DisconnectNamedPipe(self.pipe.raw()) };
        for _ in 0..4 {
            self.reset_overlapped();
            // SAFETY: the instance is overlapped; the boxed OVERLAPPED and its event stay alive and
            // unused by other operations until the completion is observed or cancelled.
            match unsafe { ConnectNamedPipe(self.pipe.raw(), Some(&mut *self.overlapped)) } {
                Ok(()) => return self.start_read(read_timeout),
                Err(error) if is_win32(&error, ERROR_PIPE_CONNECTED) => {
                    return self.start_read(read_timeout);
                }
                Err(error) if is_win32(&error, ERROR_IO_PENDING) => {
                    self.phase = Phase::Listening;
                    return Ok(Progress::Pending);
                }
                // A client connected and closed before the connect call; recycle the instance.
                Err(error) if is_win32(&error, ERROR_NO_DATA) => {
                    // SAFETY: as above, this live instance has no pending operation.
                    let _ = unsafe { DisconnectNamedPipe(self.pipe.raw()) };
                }
                Err(error) => {
                    return Err(pipe_error(
                        ErrorCode::TransactionIo,
                        "named-pipe connection failed",
                        &error,
                    ));
                }
            }
        }
        Err(MaintenanceError::new(
            ErrorCode::TransactionIo,
            "named-pipe instance could not listen",
        ))
    }

    fn start_read(&mut self, read_timeout: Duration) -> Result<Progress> {
        self.reset_overlapped();
        // SAFETY: the pipe is connected and overlapped; the boxed buffer and OVERLAPPED stay alive
        // and untouched until completion or cancellation is observed.
        let started = unsafe {
            ReadFile(
                self.pipe.raw(),
                Some(&mut self.buffer),
                None,
                Some(&mut *self.overlapped),
            )
        };
        match started {
            Ok(()) => {
                self.phase = Phase::Reading(Instant::now() + read_timeout);
                Ok(Progress::Request(self.finish_read()))
            }
            Err(error) if is_win32(&error, ERROR_IO_PENDING) => {
                self.phase = Phase::Reading(Instant::now() + read_timeout);
                Ok(Progress::Pending)
            }
            Err(error) => {
                self.phase = Phase::Held;
                Ok(Progress::Request(Err(read_error(&error))))
            }
        }
    }

    fn finish_read(&mut self) -> Result<Vec<u8>> {
        let mut transferred = 0_u32;
        // SAFETY: the read completed (its event is signaled or it finished synchronously), so the
        // OVERLAPPED result is final and the buffer holds `transferred` bytes.
        let result = unsafe {
            GetOverlappedResult(self.pipe.raw(), &*self.overlapped, &mut transferred, false)
        };
        self.phase = Phase::Held;
        result.map_err(|error| read_error(&error))?;
        let length = usize::try_from(transferred).map_err(|_| {
            MaintenanceError::new(ErrorCode::ProtocolTooLarge, "IPC request size overflowed")
        })?;
        Ok(self.buffer.get(..length).unwrap_or_default().to_vec())
    }

    /// Handles a signaled event of a Listening or Reading instance.
    fn complete(&mut self, read_timeout: Duration) -> Result<Progress> {
        match self.phase {
            Phase::Listening => {
                let mut transferred = 0_u32;
                // SAFETY: the connect operation signaled its event and its OVERLAPPED is live.
                let connected = unsafe {
                    GetOverlappedResult(self.pipe.raw(), &*self.overlapped, &mut transferred, false)
                };
                self.phase = Phase::Held;
                if connected.is_ok() {
                    self.start_read(read_timeout)
                } else {
                    self.listen(read_timeout)
                }
            }
            Phase::Reading(_) => Ok(Progress::Request(self.finish_read())),
            Phase::Held => Ok(Progress::Pending),
        }
    }

    fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<()> {
        self.reset_overlapped();
        // SAFETY: the connected pipe is overlapped; `bytes` and the OVERLAPPED outlive the
        // operation because completion or cancellation is drained before this function returns.
        let started = unsafe {
            WriteFile(
                self.pipe.raw(),
                Some(bytes),
                None,
                Some(&mut *self.overlapped),
            )
        };
        match started {
            Ok(()) => {}
            Err(error) if is_win32(&error, ERROR_IO_PENDING) => {
                // SAFETY: the event belongs to this pending operation.
                let wait = unsafe {
                    windows::Win32::System::Threading::WaitForSingleObject(
                        self.event.raw(),
                        milliseconds(timeout),
                    )
                };
                if wait != WAIT_OBJECT_0 {
                    // SAFETY: cancel only this operation and drain it before the buffers go away.
                    unsafe {
                        let _ = CancelIoEx(self.pipe.raw(), Some(&*self.overlapped));
                        let mut transferred = 0_u32;
                        let _ = GetOverlappedResult(
                            self.pipe.raw(),
                            &*self.overlapped,
                            &mut transferred,
                            true,
                        );
                    }
                    return Err(MaintenanceError::new(
                        ErrorCode::TransactionIo,
                        "IPC response write timed out",
                    ));
                }
            }
            Err(error) => {
                return Err(pipe_error(
                    ErrorCode::TransactionIo,
                    "IPC response could not be written",
                    &error,
                ));
            }
        }
        let mut transferred = 0_u32;
        // SAFETY: the write completed; this reads its final byte count.
        unsafe { GetOverlappedResult(self.pipe.raw(), &*self.overlapped, &mut transferred, false) }
            .map_err(|error| {
                pipe_error(
                    ErrorCode::TransactionIo,
                    "IPC response write did not complete",
                    &error,
                )
            })?;
        if usize::try_from(transferred).ok() != Some(bytes.len()) {
            return Err(MaintenanceError::new(
                ErrorCode::TransactionIo,
                "IPC response write was incomplete",
            ));
        }
        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        // The kernel must stop using the boxed OVERLAPPED and buffer before they are freed.
        self.cancel_pending();
    }
}

fn read_error(error: &windows::core::Error) -> MaintenanceError {
    if is_win32(error, ERROR_MORE_DATA) {
        MaintenanceError::new(
            ErrorCode::ProtocolTooLarge,
            "IPC request exceeds the message bound",
        )
    } else {
        pipe_error(
            ErrorCode::ProtocolInvalid,
            "IPC request could not be read as one bounded message",
            error,
        )
    }
}

pub(super) enum PipeEvent {
    /// A client sent one message. Its instance is held until `respond` or `release`.
    Request {
        slot: usize,
        message: Result<Vec<u8>>,
    },
    /// The stop event was signaled.
    Stop,
    /// The wake event was signaled.
    Wake,
    /// No client was connected for the whole idle timeout.
    Idle,
}

pub(super) struct PipeServer {
    instances: Vec<Instance>,
    ready: VecDeque<(usize, Result<Vec<u8>>)>,
    read_timeout: Duration,
    write_timeout: Duration,
    last_activity: Instant,
}

impl PipeServer {
    /// Claims the pipe name with `instances` listening instances.
    pub(super) fn create(
        name: &str,
        instances: u32,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self> {
        let wide = wide_null(name);
        let mut server = Self {
            instances: Vec::new(),
            ready: VecDeque::new(),
            read_timeout,
            write_timeout,
            last_activity: Instant::now(),
        };
        for index in 0..instances.max(1) {
            server
                .instances
                .push(Instance::create(&wide, index == 0, instances.max(1))?);
        }
        for slot in 0..server.instances.len() {
            server.listen(slot)?;
        }
        Ok(server)
    }

    fn listen(&mut self, slot: usize) -> Result<()> {
        let read_timeout = self.read_timeout;
        let instance = self.instance(slot)?;
        if let Progress::Request(message) = instance.listen(read_timeout)? {
            self.ready.push_back((slot, message));
        }
        Ok(())
    }

    fn instance(&mut self, slot: usize) -> Result<&mut Instance> {
        self.instances.get_mut(slot).ok_or_else(|| {
            MaintenanceError::new(ErrorCode::TransactionState, "pipe instance does not exist")
        })
    }

    /// The server handle of a held instance, for impersonating its client.
    pub(super) fn pipe(&self, slot: usize) -> Option<HANDLE> {
        self.instances
            .get(slot)
            .filter(|instance| instance.phase == Phase::Held)
            .map(|instance| instance.pipe.raw())
    }

    /// Writes one response to a held instance, then disconnects it and listens again.
    /// The write result is returned only for diagnostics; the instance is recycled either way.
    pub(super) fn respond(&mut self, slot: usize, bytes: &[u8]) -> Result<Result<()>> {
        let write_timeout = self.write_timeout;
        let written = self.instance(slot)?.write(bytes, write_timeout);
        self.last_activity = Instant::now();
        self.listen(slot)?;
        Ok(written)
    }

    /// Disconnects a held instance without a response and listens again.
    pub(super) fn release(&mut self, slot: usize) -> Result<()> {
        self.last_activity = Instant::now();
        self.listen(slot)
    }

    fn busy(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| !matches!(instance.phase, Phase::Listening))
    }

    /// Waits for the next request, stop, wake, or idle timeout.
    pub(super) fn next_event(
        &mut self,
        stop: HANDLE,
        wake: HANDLE,
        idle_timeout: Duration,
    ) -> Result<PipeEvent> {
        loop {
            if let Some((slot, message)) = self.ready.pop_front() {
                self.last_activity = Instant::now();
                return Ok(PipeEvent::Request { slot, message });
            }
            let now = Instant::now();
            let mut handles = vec![stop, wake];
            let mut slots = Vec::new();
            let mut deadline = None::<Instant>;
            for (slot, instance) in self.instances.iter().enumerate() {
                match instance.phase {
                    Phase::Listening => {}
                    Phase::Reading(read_deadline) => {
                        deadline = Some(deadline.map_or(read_deadline, |d| d.min(read_deadline)));
                    }
                    Phase::Held => continue,
                }
                handles.push(instance.event.raw());
                slots.push(slot);
            }
            let idle_deadline = (!self.busy()).then(|| self.last_activity + idle_timeout);
            let wait_until = match (deadline, idle_deadline) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            };
            let timeout = wait_until.map_or(u32::MAX, |until| {
                milliseconds(until.saturating_duration_since(now))
            });
            // SAFETY: every handle is a live event owned by this server or its caller.
            let wait = unsafe { WaitForMultipleObjects(&handles, false, timeout) };
            if wait == WAIT_TIMEOUT {
                self.expire_reads()?;
                if idle_deadline.is_some_and(|idle| Instant::now() >= idle) && !self.busy() {
                    return Ok(PipeEvent::Idle);
                }
                continue;
            }
            let index = usize::try_from(wait.0.wrapping_sub(WAIT_OBJECT_0.0)).unwrap_or(usize::MAX);
            match index {
                0 => return Ok(PipeEvent::Stop),
                1 => return Ok(PipeEvent::Wake),
                _ => {
                    let slot = slots.get(index - 2).copied().ok_or_else(|| {
                        MaintenanceError::new(ErrorCode::TransactionIo, "named-pipe wait failed")
                    })?;
                    let read_timeout = self.read_timeout;
                    let was_listening = self.instance(slot)?.phase == Phase::Listening;
                    match self.instance(slot)?.complete(read_timeout)? {
                        Progress::Request(message) => self.ready.push_back((slot, message)),
                        Progress::Pending => {
                            if was_listening {
                                self.last_activity = Instant::now();
                            }
                        }
                    }
                }
            }
        }
    }

    /// Disconnects clients that did not send a request before their deadline.
    fn expire_reads(&mut self) -> Result<()> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .instances
            .iter()
            .enumerate()
            .filter(|(_, instance)| {
                matches!(instance.phase, Phase::Reading(deadline) if deadline <= now)
            })
            .map(|(slot, _)| slot)
            .collect();
        for slot in expired {
            self.listen(slot)?;
        }
        Ok(())
    }
}

/// Opens the client end of `name` once the server end belongs to `server_process_id()`.
///
/// The process ID is compared before the client writes anything, so a process that created the
/// name first never receives a request and therefore can never impersonate the client. The
/// explicit quality of service allows the impersonation the service needs to open the caller's
/// files with the caller's rights, and no delegation.
pub(super) fn open_verified_client(
    name: &str,
    timeout: Duration,
    mut server_process_id: impl FnMut() -> Option<u32>,
) -> Result<File> {
    let wide = wide_null(name);
    let path = Path::new(name);
    let foreign = Cell::new(false);
    wait_for_pipe_ready_with(
        timeout,
        |wait_milliseconds| {
            // SAFETY: the pipe name is NUL-terminated and the wait slice is finite.
            if !unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), wait_milliseconds) }.as_bool() {
                return None;
            }
            let expected = server_process_id()?;
            let pipe = open_absolute(
                path,
                PIPE_CLIENT_ACCESS_MASK,
                FILE_SHARE_MODE(0),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL
                    | FILE_FLAG_OVERLAPPED
                    | SECURITY_SQOS_PRESENT
                    | SECURITY_IMPERSONATION,
            )
            .ok()?;
            let mut actual = 0_u32;
            // SAFETY: `pipe` is a live client pipe handle and `actual` is a valid out pointer.
            unsafe { GetNamedPipeServerProcessId(raw_handle(&pipe), &mut actual) }.ok()?;
            if actual == expected {
                Some(pipe)
            } else {
                foreign.set(true);
                None
            }
        },
        thread::sleep,
    )
    .ok_or_else(|| {
        MaintenanceError::new(
            ErrorCode::TransactionIo,
            if foreign.get() {
                "shared maintenance pipe is served by another process"
            } else {
                "shared maintenance pipe did not become ready"
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread::JoinHandle,
    };

    use windows::Win32::System::Threading::SetEvent;

    use super::*;
    use crate::windows::{SendHandle, transact_pipe_message_with_timeout};

    static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

    fn unique_name() -> String {
        format!(
            r"\\.\pipe\SE7ENService-server-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        )
    }

    struct EchoServer {
        stop: KernelHandle,
        thread: Option<JoinHandle<Result<()>>>,
    }

    impl EchoServer {
        fn start(name: &str, instances: u32, read_timeout: Duration) -> Self {
            let stop = create_event(true, false).unwrap();
            let thread_stop = SendHandle(stop.raw());
            let thread_name = name.to_owned();
            let (ready, started) = mpsc::channel();
            let thread = thread::spawn(move || {
                let created =
                    PipeServer::create(&thread_name, instances, read_timeout, PIPE_WRITE_TIMEOUT);
                let mut server = match created {
                    Ok(server) => {
                        ready.send(Ok(())).unwrap();
                        server
                    }
                    Err(error) => {
                        ready.send(Err(error.clone())).unwrap();
                        return Err(error);
                    }
                };
                let wake = create_event(false, false)?;
                let stop = thread_stop;
                loop {
                    match server.next_event(stop.0, wake.raw(), Duration::from_secs(60))? {
                        PipeEvent::Request { slot, message } => {
                            let reply = match message {
                                Ok(bytes) => bytes,
                                Err(error) => error.detail().as_bytes().to_vec(),
                            };
                            let _ = server.respond(slot, &reply)?;
                        }
                        PipeEvent::Stop | PipeEvent::Idle => return Ok(()),
                        PipeEvent::Wake => {}
                    }
                }
            });
            started.recv().unwrap().expect("create test pipe server");
            Self {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for EchoServer {
        fn drop(&mut self) {
            // SAFETY: the stop event is owned by this value and outlives the joined thread.
            let _ = unsafe { SetEvent(self.stop.raw()) };
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap().unwrap();
            }
        }
    }

    fn own_process() -> Option<u32> {
        Some(std::process::id())
    }

    fn call(name: &str, request: &[u8]) -> Result<Vec<u8>> {
        let pipe = open_verified_client(name, Duration::from_secs(5), own_process)?;
        transact_pipe_message_with_timeout(raw_handle(&pipe), request, Duration::from_secs(5))
    }

    #[test]
    fn a_silent_client_does_not_block_other_clients() {
        let name = unique_name();
        let _server = EchoServer::start(&name, SERVICE_PIPE_INSTANCES, Duration::from_secs(60));
        // Connect without ever writing, as any authenticated user could.
        let silent = open_verified_client(&name, Duration::from_secs(5), own_process).unwrap();
        let started = Instant::now();
        assert_eq!(call(&name, b"second").unwrap(), b"second");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(silent);
    }

    #[test]
    fn a_silent_client_is_disconnected_after_the_read_timeout() {
        let name = unique_name();
        let _server = EchoServer::start(&name, 1, Duration::from_millis(200));
        let silent = open_verified_client(&name, Duration::from_secs(5), own_process).unwrap();
        thread::sleep(Duration::from_millis(800));
        // The only instance was recycled, so the late request fails and a new client succeeds.
        assert!(
            transact_pipe_message_with_timeout(
                raw_handle(&silent),
                b"late",
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert_eq!(call(&name, b"next").unwrap(), b"next");
    }

    #[test]
    fn requests_are_served_one_after_another_on_every_instance() {
        let name = unique_name();
        let _server = EchoServer::start(&name, 2, PIPE_READ_TIMEOUT);
        for round in 0..6_u8 {
            assert_eq!(call(&name, &[round]).unwrap(), [round]);
        }
    }

    #[test]
    fn the_service_refuses_a_name_that_another_process_created_first() {
        let name = unique_name();
        let squatter = Instance::create(&wide_null(&name), false, 4).unwrap();
        let error = PipeServer::create(&name, 4, PIPE_READ_TIMEOUT, PIPE_WRITE_TIMEOUT)
            .err()
            .expect("a pipe name owned by another server must be refused");
        assert_eq!(
            error.detail(),
            "local maintenance pipe name is already in use"
        );
        drop(squatter);
    }

    #[test]
    fn the_name_stays_claimed_while_the_server_runs() {
        let name = unique_name();
        let _server = EchoServer::start(&name, 1, PIPE_READ_TIMEOUT);
        for _ in 0..3 {
            assert_eq!(call(&name, b"ping").unwrap(), b"ping");
            assert!(
                Instance::create(&wide_null(&name), true, 1).is_err(),
                "a second first instance must fail while the service owns the name"
            );
        }
    }

    #[test]
    fn the_client_writes_nothing_to_a_server_in_another_process() {
        let name = unique_name();
        let _server = EchoServer::start(&name, 1, PIPE_READ_TIMEOUT);
        let other_process = std::process::id().wrapping_add(4);
        let error = open_verified_client(&name, Duration::from_millis(300), || Some(other_process))
            .expect_err("a foreign pipe server must be refused");
        assert_eq!(
            error.detail(),
            "shared maintenance pipe is served by another process"
        );
        // The refused attempts did not leave the server stuck.
        assert_eq!(call(&name, b"after").unwrap(), b"after");
    }

    #[test]
    fn an_oversized_request_is_rejected() {
        let name = unique_name();
        let _server = EchoServer::start(&name, 1, PIPE_READ_TIMEOUT);
        let reply = call(&name, &vec![b'x'; MAX_IPC_MESSAGE_BYTES + 1]).unwrap();
        assert_eq!(reply, b"IPC request exceeds the message bound");
    }
}
