use std::{
    io::{self, Read},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::{ParsedTransferOutput, ProcessInvocation, TransferOutputParser};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
    cancelled: bool,
    output: ParsedTransferOutput,
    stderr_had_output: bool,
    redacted_invocation: String,
}

impl ProcessOutcome {
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub const fn signal(&self) -> Option<i32> {
        self.signal
    }

    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn output(&self) -> &ParsedTransferOutput {
        &self.output
    }

    pub fn redacted_invocation(&self) -> &str {
        &self.redacted_invocation
    }

    pub const fn stderr_had_output(&self) -> bool {
        self.stderr_had_output
    }

    pub fn succeeded(&self) -> bool {
        !self.cancelled && self.exit_code == Some(0) && self.signal.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
    Spawn(String),
    Io(String),
    ProcessGroup(String),
    OutputReader(String),
    OrphanedProcessGroup,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(reason) => write!(formatter, "could not start controlled process: {reason}"),
            Self::Io(reason) => write!(formatter, "controlled process I/O failed: {reason}"),
            Self::ProcessGroup(reason) => write!(formatter, "process-group operation failed: {reason}"),
            Self::OutputReader(reason) => write!(formatter, "process output could not be read: {reason}"),
            Self::OrphanedProcessGroup => {
                formatter.write_str("controlled process group did not terminate cleanly")
            }
        }
    }
}

impl std::error::Error for ProcessError {}

#[derive(Debug, Clone, Copy)]
pub struct ProcessSupervisor {
    termination_grace: Duration,
    poll_interval: Duration,
}

impl Default for ProcessSupervisor {
    fn default() -> Self {
        Self {
            termination_grace: Duration::from_millis(500),
            poll_interval: Duration::from_millis(10),
        }
    }
}

impl ProcessSupervisor {
    pub fn with_termination_grace(termination_grace: Duration) -> Self {
        Self {
            termination_grace,
            ..Self::default()
        }
    }

    /// Runs only a pre-built typed invocation. No shell or caller-provided
    /// command string is accepted by this boundary.
    pub fn run<F>(
        &self,
        invocation: &ProcessInvocation,
        should_cancel: F,
    ) -> Result<ProcessOutcome, ProcessError>
    where
        F: Fn() -> bool,
    {
        let mut command = Command::new(invocation.program());
        command
            .args(invocation.arguments())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command)?;
        let mut child = command.spawn().map_err(|error| ProcessError::Spawn(error.to_string()))?;
        let process_group_id = child.id() as i32;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                return Err(cleanup_after_spawn_failure(
                    &mut child,
                    process_group_id,
                    self.termination_grace,
                    self.poll_interval,
                    "stdout pipe was not available",
                ));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                return Err(cleanup_after_spawn_failure(
                    &mut child,
                    process_group_id,
                    self.termination_grace,
                    self.poll_interval,
                    "stderr pipe was not available",
                ));
            }
        };
        let stdout_reader = thread::spawn(|| read_output(stdout));
        let stderr_reader = thread::spawn(|| drain_output(stderr));

        let mut cancelled = false;
        let status = loop {
            if !cancelled && should_cancel() {
                cancelled = true;
                break match terminate_child_group(
                    &mut child,
                    process_group_id,
                    self.termination_grace,
                    self.poll_interval,
                ) {
                    Ok(status) => status,
                    Err(error) => {
                        return Err(cleanup_after_runtime_error(
                            &mut child,
                            process_group_id,
                            self.termination_grace,
                            self.poll_interval,
                            error,
                        ));
                    }
                };
            } else {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => thread::sleep(self.poll_interval),
                    Err(error) => {
                        return Err(cleanup_after_runtime_error(
                            &mut child,
                            process_group_id,
                            self.termination_grace,
                            self.poll_interval,
                            ProcessError::Io(error.to_string()),
                        ));
                    }
                }
            }
        };

        let cleanup = if process_group_exists(process_group_id) {
            cleanup_process_group(
                process_group_id,
                self.termination_grace,
                self.poll_interval,
            )
        } else {
            Ok(())
        };

        let stdout = join_output(stdout_reader)?;
        let stderr_had_output = join_stderr(stderr_reader)?;
        cleanup?;
        Ok(ProcessOutcome {
            exit_code: status.code(),
            signal: signal_from_status(&status),
            cancelled,
            output: stdout,
            stderr_had_output,
            redacted_invocation: invocation.preview(),
        })
    }
}

const OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

fn read_output<R>(mut reader: R) -> io::Result<ParsedTransferOutput>
where
    R: Read,
{
    let mut parser = TransferOutputParser::new();
    let mut output = ParsedTransferOutput::default();
    let mut chunk = [0u8; OUTPUT_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        for event in parser.feed(&chunk[..read]) {
            output.push(event);
        }
    }
    for event in parser.finish() {
        output.push(event);
    }
    Ok(output)
}

fn drain_output<R>(mut reader: R) -> io::Result<bool>
where
    R: Read,
{
    let mut chunk = [0u8; OUTPUT_CHUNK_BYTES];
    let mut had_output = false;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        had_output = true;
    }
    Ok(had_output)
}

fn join_output(
    reader: thread::JoinHandle<io::Result<ParsedTransferOutput>>,
) -> Result<ParsedTransferOutput, ProcessError> {
    let result = reader
        .join()
        .map_err(|_| ProcessError::OutputReader("output reader thread panicked".to_owned()))?;
    result.map_err(|error| ProcessError::OutputReader(error.to_string()))
}

fn join_stderr(reader: thread::JoinHandle<io::Result<bool>>) -> Result<bool, ProcessError> {
    reader
        .join()
        .map_err(|_| ProcessError::OutputReader("stderr reader thread panicked".to_owned()))?
        .map_err(|error| ProcessError::OutputReader(error.to_string()))
}

fn cleanup_after_spawn_failure(
    child: &mut Child,
    process_group_id: i32,
    termination_grace: Duration,
    poll_interval: Duration,
    reason: &str,
) -> ProcessError {
    match terminate_child_group(child, process_group_id, termination_grace, poll_interval) {
        Ok(_) => ProcessError::Io(reason.to_owned()),
        Err(error) => error,
    }
}

fn cleanup_after_runtime_error(
    child: &mut Child,
    process_group_id: i32,
    termination_grace: Duration,
    poll_interval: Duration,
    original_error: ProcessError,
) -> ProcessError {
    match cleanup_process_group(process_group_id, termination_grace, poll_interval) {
        Ok(()) => {
            let _ = child.try_wait();
            original_error
        }
        Err(cleanup_error) => cleanup_error,
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) -> Result<(), ProcessError> {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) -> Result<(), ProcessError> {
    Err(ProcessError::ProcessGroup(
        "process groups are required on the supported Linux platform".to_owned(),
    ))
}

#[cfg(unix)]
fn terminate_child_group(
    child: &mut Child,
    process_group_id: i32,
    termination_grace: Duration,
    poll_interval: Duration,
) -> Result<ExitStatus, ProcessError> {
    let mut signal_error = send_group_signal(process_group_id, libc::SIGTERM).err();
    let deadline = Instant::now() + termination_grace;
    let mut status = None;
    while Instant::now() < deadline {
        if status.is_none() {
            match child.try_wait() {
                Ok(child_status) => status = child_status,
                Err(error) => {
                    signal_error.get_or_insert(ProcessError::Io(error.to_string()));
                    break;
                }
            }
        }
        if !process_group_exists(process_group_id) {
            break;
        }
        thread::sleep(poll_interval);
    }
    let kill_error = if process_group_exists(process_group_id) {
        send_group_signal(process_group_id, libc::SIGKILL).err()
    } else {
        None
    };
    let wait_error = if status.is_none() && kill_error.is_none() {
        match child.wait() {
            Ok(child_status) => {
                status = Some(child_status);
                None
            }
            Err(error) => Some(ProcessError::Io(error.to_string())),
        }
    } else {
        None
    };
    let group_error = wait_for_group_exit(process_group_id, termination_grace, poll_interval).err();
    if let Some(error) = kill_error.or(wait_error).or(signal_error).or(group_error) {
        return Err(error);
    }
    status.ok_or_else(|| ProcessError::Io("cancelled process had no exit status".to_owned()))
}

#[cfg(unix)]
fn cleanup_process_group(
    process_group_id: i32,
    termination_grace: Duration,
    poll_interval: Duration,
) -> Result<(), ProcessError> {
    let mut signal_error = send_group_signal(process_group_id, libc::SIGTERM).err();
    if process_group_exists(process_group_id) {
        thread::sleep(termination_grace);
        if process_group_exists(process_group_id) {
            if let Err(error) = send_group_signal(process_group_id, libc::SIGKILL) {
                signal_error.get_or_insert(error);
            }
        }
    }
    let group_error = wait_for_group_exit(process_group_id, termination_grace, poll_interval).err();
    signal_error.or(group_error).map_or(Ok(()), Err)
}

#[cfg(not(unix))]
fn terminate_child_group(
    child: &mut Child,
    _process_group_id: i32,
    _termination_grace: Duration,
    _poll_interval: Duration,
) -> Result<ExitStatus, ProcessError> {
    child
        .kill()
        .map_err(|error| ProcessError::ProcessGroup(error.to_string()))?;
    child
        .wait()
        .map_err(|error| ProcessError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn cleanup_process_group(
    _process_group_id: i32,
    _termination_grace: Duration,
    _poll_interval: Duration,
) -> Result<(), ProcessError> {
    Ok(())
}

#[cfg(unix)]
fn wait_for_group_exit(
    process_group_id: i32,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), ProcessError> {
    let deadline = Instant::now() + timeout;
    while process_group_exists(process_group_id) && Instant::now() < deadline {
        thread::sleep(poll_interval);
    }
    if process_group_exists(process_group_id) {
        Err(ProcessError::OrphanedProcessGroup)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn send_group_signal(process_group_id: i32, signal: i32) -> Result<(), ProcessError> {
    let result = unsafe { libc::kill(-process_group_id, signal) };
    if result == 0 {
        return Ok(());
    }
    if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(ProcessError::ProcessGroup(
            io::Error::last_os_error().to_string(),
        ))
    }
}

#[cfg(unix)]
fn process_group_exists(process_group_id: i32) -> bool {
    let result = unsafe { libc::kill(-process_group_id, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_group_exists(_process_group_id: i32) -> bool {
    false
}

#[cfg(unix)]
fn signal_from_status(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_from_status(_status: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{atomic::{AtomicBool, Ordering}, Arc},
        thread,
        time::Duration,
    };

    use super::ProcessSupervisor;
    use crate::process::test_process_invocation;

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_the_process_group_without_orphans() {
        let marker = std::env::temp_dir().join(format!(
            "syncplus-runner-child-{}",
            std::process::id()
        ));
        let script = format!(
            "trap '' TERM; sleep 30 & child=$!; echo $child > '{}'; wait",
            marker.display()
        );
        let _ = fs::remove_file(&marker);
        let invocation = test_process_invocation("/bin/sh", &["-c", &script]);
        let cancelled = Arc::new(AtomicBool::new(false));
        let trigger = Arc::clone(&cancelled);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            trigger.store(true, Ordering::Relaxed);
        });

        let outcome = ProcessSupervisor::with_termination_grace(Duration::from_millis(100))
            .run(&invocation, || cancelled.load(Ordering::Relaxed))
            .expect("process group should terminate");
        assert!(outcome.cancelled());
        assert!(!outcome.succeeded());

        let child_pid = wait_for_pid(&marker);
        assert!(child_pid.is_some(), "the descendant should have started");
        assert_process_gone(child_pid.expect("child pid was written"));
        let _ = fs::remove_file(marker);
    }

    #[cfg(unix)]
    fn wait_for_pid(path: &PathBuf) -> Option<i32> {
        for _ in 0..100 {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse::<i32>() {
                    return Some(pid);
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        None
    }

    #[cfg(unix)]
    fn assert_process_gone(pid: i32) {
        for _ in 0..100 {
            let exists = unsafe { libc::kill(pid, 0) == 0 };
            if !exists {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("descendant process {pid} survived cancellation");
    }

    #[test]
    fn successful_typed_invocation_reports_redacted_command_and_parsed_output() {
        let invocation = test_process_invocation("/bin/printf", &[">f+++++++++ file.txt\\n"]);
        let outcome = ProcessSupervisor::default()
            .run(&invocation, || false)
            .expect("typed process should run");
        assert!(outcome.succeeded());
        assert!(outcome.redacted_invocation().contains("/bin/printf"));
        assert_eq!(outcome.output().itemized().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn stderr_presence_is_retained_without_persisting_raw_process_output() {
        let invocation = test_process_invocation("/bin/sh", &["-c", "printf warning >&2"]);
        let outcome = ProcessSupervisor::default()
            .run(&invocation, || false)
            .expect("typed process should run");
        assert!(outcome.succeeded());
        assert!(outcome.stderr_had_output());
        assert!(outcome.output().diagnostics().is_empty());
    }
}
