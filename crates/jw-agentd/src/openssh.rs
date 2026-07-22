use std::ffi::OsString;
use std::path::Path;

use tokio::process::Command;

pub(crate) const LOOPBACK_HOST: &str = "127.0.0.1";
pub(crate) const LOOPBACK_HOST_ALIAS: &str = "jw-agent-loopback";
const LOOPBACK_PORT: &str = "22";

const COMMON_OPTIONS: &[&str] = &[
    "BatchMode=no",
    "NumberOfPasswordPrompts=1",
    "PreferredAuthentications=password",
    "PasswordAuthentication=yes",
    "PubkeyAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "GSSAPIAuthentication=no",
    "IdentitiesOnly=yes",
    "StrictHostKeyChecking=yes",
];

const CONFINEMENT_OPTIONS: &[&str] = &[
    "GlobalKnownHostsFile=/dev/null",
    "CheckHostIP=no",
    "ConnectTimeout=5",
    "ConnectionAttempts=1",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=2",
    "ClearAllForwardings=yes",
    "ForwardAgent=no",
    "PermitLocalCommand=no",
    "LocalCommand=none",
    "ControlMaster=no",
    "ControlPath=none",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenSshMode {
    Terminal,
    Sftp,
}

pub(crate) fn arguments(known_hosts: &Path, username: &str, mode: OpenSshMode) -> Vec<OsString> {
    let mut arguments = vec![OsString::from("-F"), OsString::from("/dev/null")];
    append_options(&mut arguments, COMMON_OPTIONS);
    let mut known_hosts_option = OsString::from("UserKnownHostsFile=");
    known_hosts_option.push(known_hosts);
    arguments.push(OsString::from("-o"));
    arguments.push(known_hosts_option);
    arguments.push(OsString::from("-o"));
    arguments.push(OsString::from(format!(
        "HostKeyAlias={LOOPBACK_HOST_ALIAS}"
    )));
    append_options(&mut arguments, CONFINEMENT_OPTIONS);
    match mode {
        OpenSshMode::Terminal => append_options(
            &mut arguments,
            &["EscapeChar=none", "LogLevel=ERROR", "RequestTTY=force"],
        ),
        OpenSshMode::Sftp => {
            append_options(&mut arguments, &["RequestTTY=no", "LogLevel=ERROR"]);
            arguments.push(OsString::from("-s"));
        }
    }
    arguments.extend([
        OsString::from("-p"),
        OsString::from(LOOPBACK_PORT),
        OsString::from("-l"),
        OsString::from(username),
        OsString::from(LOOPBACK_HOST),
    ]);
    if mode == OpenSshMode::Sftp {
        arguments.push(OsString::from("sftp"));
    }
    arguments
}

pub(crate) fn configure_askpass(
    command: &mut Command,
    askpass_executable: &Path,
    fifo_path: &Path,
    mode: OpenSshMode,
) {
    command
        .env_clear()
        .env("DISPLAY", "jw-agent:0")
        .env("LANG", "C.UTF-8")
        .env("SSH_ASKPASS", askpass_executable)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("JW_AGENT_ASKPASS_MODE", "1")
        .env("JW_AGENT_ASKPASS_FIFO", fifo_path);
    if mode == OpenSshMode::Terminal {
        command.env("TERM", "xterm-256color");
    }
}

fn append_options(arguments: &mut Vec<OsString>, options: &[&str]) {
    for option in options {
        arguments.push(OsString::from("-o"));
        arguments.push(OsString::from(option));
    }
}

#[cfg(test)]
mod tests {
    use super::{LOOPBACK_HOST, LOOPBACK_HOST_ALIAS, OpenSshMode, arguments};
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn terminal_and_sftp_share_the_exact_confinement_policy() {
        let terminal = arguments(
            Path::new("/fixture/known-hosts"),
            "operator",
            OpenSshMode::Terminal,
        );
        let sftp = arguments(
            Path::new("/fixture/known-hosts"),
            "operator",
            OpenSshMode::Sftp,
        );
        for required in [
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=/fixture/known-hosts",
            "GlobalKnownHostsFile=/dev/null",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "ControlMaster=no",
        ] {
            assert!(terminal.iter().any(|value| value == OsStr::new(required)));
            assert!(sftp.iter().any(|value| value == OsStr::new(required)));
        }
        assert!(
            terminal
                .iter()
                .any(|value| value == OsStr::new("EscapeChar=none"))
        );
        assert!(
            terminal
                .iter()
                .any(|value| value == OsStr::new("RequestTTY=force"))
        );
        assert!(
            sftp.iter()
                .any(|value| value == OsStr::new("RequestTTY=no"))
        );
        assert_eq!(
            terminal.last().and_then(|value| value.to_str()),
            Some(LOOPBACK_HOST)
        );
        assert_eq!(sftp.last().and_then(|value| value.to_str()), Some("sftp"));
        assert_eq!(LOOPBACK_HOST_ALIAS, "jw-agent-loopback");
    }
}
