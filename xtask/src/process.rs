#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT_BYTES: usize = 128 * 1_024;
const TERMINATION_GRACE: Duration = Duration::from_secs(2);

pub(crate) struct Captured {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
}

pub(crate) fn run_capture(
    program: &OsStr,
    arguments: &[OsString],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    run_capture_in(None, program, arguments, input, timeout)
}

pub(crate) fn run_capture_in(
    working_directory: Option<&Path>,
    program: &OsStr,
    arguments: &[OsString],
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Captured, String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", program.to_string_lossy()))?;

    let Some(stdout) = child.stdout.take() else {
        return Err(String::from("child stdout is unavailable"));
    };
    let Some(stderr) = child.stderr.take() else {
        return Err(String::from("child stderr is unavailable"));
    };
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));
    let input_writer = if let Some(bytes) = input {
        let Some(mut stdin) = child.stdin.take() else {
            return Err(String::from("child stdin is unavailable"));
        };
        let owned = bytes.to_vec();
        Some(thread::spawn(move || {
            stdin
                .write_all(&owned)
                .map_err(|error| format!("cannot write child stdin: {error}"))
        }))
    } else {
        None
    };

    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .map_err(|error| format!("cannot wait for {}: {error}", program.to_string_lossy()))?
        {
            Some(status) => break status,
            None if started.elapsed() >= timeout => {
                let status = terminate_process_group(&mut child)?;
                let _input = join_input_writer(input_writer);
                let _stdout = stdout_reader.join();
                let _stderr = stderr_reader.join();
                return Err(format!(
                    "{} exceeded {} seconds and exited with {status}",
                    program.to_string_lossy(),
                    timeout.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };

    let input_result = join_input_writer(input_writer);
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| String::from("stdout reader failed"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| String::from("stderr reader failed"))??;
    if status.success() {
        input_result?;
    }
    Ok(Captured {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

pub(crate) fn safe_output(bytes: &[u8], truncated: bool) -> String {
    let mut value = String::from_utf8_lossy(bytes).trim().to_owned();
    if value.len() > 2_048 {
        value.truncate(2_048);
        value.push_str("...[display capped]");
    }
    if truncated {
        value.push_str("...[capture capped]");
    }
    value
}

fn join_input_writer(writer: Option<thread::JoinHandle<Result<(), String>>>) -> Result<(), String> {
    match writer {
        Some(writer) => writer
            .join()
            .map_err(|_| String::from("stdin writer failed"))?,
        None => Ok(()),
    }
}

fn read_capped<R: Read>(mut reader: R) -> Result<(Vec<u8>, bool), String> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 8 * 1_024];
    let mut truncated = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read child output: {error}"))?;
        if count == 0 {
            return Ok((kept, truncated));
        }
        let remaining = OUTPUT_LIMIT_BYTES.saturating_sub(kept.len());
        let take = remaining.min(count);
        kept.extend_from_slice(&buffer[..take]);
        if take < count {
            truncated = true;
        }
    }
}

fn terminate_process_group(child: &mut Child) -> Result<ExitStatus, String> {
    if signal_process_group(child.id(), "TERM").is_err() {
        child
            .kill()
            .map_err(|error| format!("cannot stop timed-out process: {error}"))?;
    }
    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot wait for timed-out process: {error}"))?
        {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _group_kill = signal_process_group(child.id(), "KILL");
    let _child_kill = child.kill();
    child
        .wait()
        .map_err(|error| format!("cannot reap timed-out process: {error}"))
}

fn signal_process_group(process_id: u32, signal: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .args([
            OsString::from(format!("-{signal}")),
            OsString::from("--"),
            OsString::from(format!("-{process_id}")),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot signal process group: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("process-group signal exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{OUTPUT_LIMIT_BYTES, run_capture};
    use std::ffi::{OsStr, OsString};
    use std::time::{Duration, Instant};

    #[test]
    fn output_is_drained_but_capture_is_bounded() -> Result<(), String> {
        let arguments = [
            OsString::from("-c"),
            OsString::from("yes x | head -c 200000"),
        ];
        let captured = run_capture(
            OsStr::new("/bin/sh"),
            &arguments,
            None,
            Duration::from_secs(3),
        )?;
        assert!(captured.status.success());
        assert_eq!(captured.stdout.len(), OUTPUT_LIMIT_BYTES);
        assert!(captured.stdout_truncated);
        Ok(())
    }

    #[test]
    fn timeout_terminates_the_spawned_process_group() -> Result<(), String> {
        let arguments = [OsString::from("-c"), OsString::from("sleep 30 & wait")];
        let started = Instant::now();
        let result = run_capture(
            OsStr::new("/bin/sh"),
            &arguments,
            None,
            Duration::from_millis(100),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        Ok(())
    }
}
