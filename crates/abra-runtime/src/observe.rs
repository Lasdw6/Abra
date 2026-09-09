//! Bounded guest observation for workspace snapshots.

use clap::Args;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "dev.abra.observed/3";
const MAX_FILE: usize = 240 * 1024;
const MAX_TEXT: usize = 1024 * 1024;
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "fish", "ksh"];
const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "python3", "ruby", "perl", "bun", "deno",
];
const RUNTIMES: &[&str] = &[
    "node",
    "npm",
    "python3",
    "rustc",
    "cargo",
    "go",
    "java",
    "ruby",
    "bun",
    "deno",
    "codex",
    "google-chrome",
];
const LIMITATIONS: &[&str] = &[
    "observation_is_not_a_restart_guarantee",
    "environment_allowlist",
    "observer_network_namespace_only",
    "external_file_contents_not_captured",
    "app_checkpoints_require_adapters",
];

#[derive(Args, Clone, Debug)]
pub struct ObserveArgs {
    #[arg(long, default_value = "/workspace")]
    pub workspace: PathBuf,

    #[arg(long)]
    pub once: bool,

    #[arg(long, requires = "once")]
    pub barrier: Option<String>,

    #[arg(long = "proc", default_value = "/proc")]
    pub r#proc: PathBuf,

    #[arg(long, conflicts_with_all = ["cgroup", "process_group"])]
    pub all: bool,

    #[arg(long, conflicts_with = "process_group")]
    pub cgroup: Option<String>,

    #[arg(long = "process-group")]
    pub process_group: Option<i32>,

    #[arg(long, default_value_t = 2.0)]
    pub interval: f64,

    #[arg(long = "environment-interval", default_value_t = 300.0)]
    pub environment_interval: f64,

    #[arg(long = "runtime-dirs", default_value = "/usr/local/bin:/usr/bin:/bin")]
    pub runtime_dirs: String,

    #[arg(long = "cgroup-root", default_value = "/sys/fs/cgroup")]
    pub cgroup_root: PathBuf,
}

#[derive(Clone, Debug)]
struct ProcessMeta {
    pid: i64,
    state: String,
    ppid: i64,
    group: i64,
    start: u64,
}

type Errors = Vec<Value>;

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn canonical_time(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = duration.as_secs().min(i64::MAX as u64) as _;
    let mut output = unsafe { std::mem::zeroed::<libc::tm>() };
    unsafe { libc::gmtime_r(&seconds, &mut output) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        output.tm_year + 1900,
        output.tm_mon + 1,
        output.tm_mday,
        output.tm_hour,
        output.tm_min,
        output.tm_sec,
        duration.subsec_millis()
    )
}

fn now() -> String {
    canonical_time(SystemTime::now())
}

fn limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut handle = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(8192) + 1);
    Read::by_ref(&mut handle)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn text(path: &Path) -> io::Result<String> {
    let bytes = limited(path, MAX_TEXT)?;
    if bytes.len() > MAX_TEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "collector input exceeds 1 MiB",
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn report(errors: &mut Errors, collector: &str, code: &str) {
    if let Some(row) = errors.iter_mut().find(|row| {
        row.get("collector").and_then(Value::as_str) == Some(collector)
            && row.get("code").and_then(Value::as_str) == Some(code)
    }) {
        if let Some(count) = row.get_mut("count") {
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
    } else if errors.len() < 64 {
        errors.push(json!({"collector": collector, "code": code, "count": 1}));
    }
}

fn report_io(errors: &mut Errors, collector: &str, error: &io::Error) {
    let code = match error.kind() {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NotFound => "missing_or_exited",
        _ => "unavailable",
    };
    report(errors, collector, code);
}

fn parse_stat(path: &Path) -> io::Result<ProcessMeta> {
    let value = text(path)?;
    let close = value
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?;
    let pid = value[..close]
        .split_once(' ')
        .map(|part| part.0)
        .unwrap_or(&value[..close])
        .parse::<i64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed proc pid"))?;
    let fields: Vec<&str> = value[close + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short proc stat",
        ));
    }
    let number = |index: usize| {
        fields[index]
            .parse::<i64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))
    };
    Ok(ProcessMeta {
        pid,
        state: fields[0].to_owned(),
        ppid: number(1)?,
        group: number(2)?,
        start: fields[19]
            .parse::<u64>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed start ticks"))?,
    })
}

fn secret_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "pass",
        "secret",
        "token",
        "api-key",
        "api_key",
        "apikey",
        "access-key",
        "access_key",
        "accesskey",
        "private-key",
        "private_key",
        "privatekey",
        "auth",
        "credential",
        "cookie",
        "bearer",
    ]
    .iter()
    .any(|part| value.contains(part))
}

fn token_at_start(value: &str) -> bool {
    let prefixes = [
        "sk-",
        "sk_live_",
        "sk_test_",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxa-",
        "xoxb-",
        "xoxp-",
        "-----BEGIN",
    ];
    if prefixes.iter().any(|prefix| value.starts_with(prefix)) {
        return true;
    }
    (value.starts_with("eyJ") && value[3..].contains('.'))
        || (value.starts_with("AKIA")
            && value.len() == 20
            && value.as_bytes()[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
}

fn known_token_span(value: &str) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    let prefixes = [
        "sk-live_",
        "sk-test_",
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxa-",
        "xoxb-",
        "xoxp-",
    ];
    for index in 0..bytes.len() {
        if !value.is_char_boundary(index) {
            continue;
        }
        if index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_') {
            continue;
        }
        for prefix in prefixes {
            if value[index..].starts_with(prefix) {
                let mut end = index + prefix.len();
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
                {
                    end += 1;
                }
                if end >= index + prefix.len() + 6 {
                    return Some((index, end));
                }
            }
        }
        if value[index..].starts_with("AKIA") && index + 20 <= bytes.len() {
            let end = index + 20;
            if bytes[index + 4..end]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            {
                return Some((index, end));
            }
        }
        if value[index..].starts_with("eyJ") {
            let mut end = index + 3;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
            {
                end += 1;
            }
            if end >= index + 13 && end < bytes.len() && bytes[end] == b'.' {
                end += 1;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
                {
                    end += 1;
                }
                return Some((index, end));
            }
        }
    }
    None
}

fn redact_authorization(mut value: String) -> String {
    let mut offset = 0;
    loop {
        let lower = value[offset..].to_ascii_lowercase();
        let found = ["bearer ", "basic "]
            .into_iter()
            .filter_map(|prefix| lower.find(prefix).map(|index| (index, prefix.len())))
            .min_by_key(|item| item.0);
        let Some((relative, prefix_len)) = found else {
            break;
        };
        let start = offset + relative;
        let secret_start = start + prefix_len;
        let end = value[secret_start..]
            .find(char::is_whitespace)
            .map(|index| secret_start + index)
            .unwrap_or(value.len());
        value.replace_range(secret_start..end, "<redacted>");
        offset = secret_start + "<redacted>".len();
        if offset >= value.len() {
            break;
        }
    }
    value
}

fn redact_value(value: &str) -> (String, bool) {
    if token_at_start(value) {
        return ("<redacted>".to_owned(), true);
    }
    let mut changed = redact_authorization(value.to_owned());
    while let Some((start, end)) = known_token_span(&changed) {
        changed.replace_range(start..end, "<redacted>");
    }

    let words: Vec<&str> = changed.split_whitespace().collect();
    if words.iter().enumerate().any(|(index, word)| {
        let raw = word.trim_matches(['\'', '\"']);
        let flag = raw.trim_start_matches('-');
        raw.starts_with('-')
            && secret_name(flag.split_once('=').map(|part| part.0).unwrap_or(flag))
            && (word.contains('=') || index + 1 < words.len())
    }) {
        return ("<redacted>".to_owned(), true);
    }
    let lower = changed.to_ascii_lowercase();
    if let Some(scheme) = lower.find("://") {
        let after = scheme + 3;
        let authority_end = changed[after..]
            .find(['/', '?', '#'])
            .map(|index| after + index)
            .unwrap_or(changed.len());
        if changed[after..authority_end].contains('@') || changed[authority_end..].contains('#') {
            return ("<redacted>".to_owned(), true);
        }
        if let Some(query) = changed[authority_end..].find('?') {
            let query = authority_end + query + 1;
            for pair in changed[query..].split('&') {
                let key = pair.split_once('=').map(|part| part.0).unwrap_or(pair);
                if secret_name(&percent_decode(key)) {
                    return ("<redacted>".to_owned(), true);
                }
            }
        }
    }
    let was_changed = changed != value;
    (changed, was_changed)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            if let (Some(high), Some(low)) = (digit(bytes[index + 1]), digit(bytes[index + 2])) {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn basename(value: &str) -> &str {
    value
        .rsplit('/')
        .next()
        .unwrap_or(value)
        .trim_start_matches('-')
}

fn shell_words_safe(value: &str) -> bool {
    if value
        .chars()
        .any(|character| ";$`|&<>\n(){}'\"\\".contains(character))
    {
        return false;
    }
    let words: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
    !words.is_empty() && !SHELLS.contains(&basename(&words[0])) && !redact_argv(&words).1
}

fn redact_argv(argv: &[String]) -> (Vec<String>, bool) {
    let executable = argv.first().map(|item| basename(item)).unwrap_or("");
    let mut output = Vec::with_capacity(argv.len());
    let mut redacted = false;
    let mut hide_next = false;
    let mut opaque_next = false;
    for value in argv {
        if opaque_next {
            let safe = SHELLS.contains(&executable) && shell_words_safe(value);
            output.push(if safe {
                value.clone()
            } else {
                redacted = true;
                "<redacted>".to_owned()
            });
            opaque_next = false;
            continue;
        }
        if (SHELLS.contains(&executable) && value.starts_with('-') && value[1..].contains('c'))
            || (INTERPRETERS.contains(&executable)
                && matches!(value.as_str(), "-c" | "-e" | "--eval"))
        {
            opaque_next = true;
        }
        if hide_next {
            output.push("<redacted>".to_owned());
            redacted = true;
            hide_next = false;
            continue;
        }
        if let Some((name, _)) = value.split_once('=') {
            if secret_name(name.trim_start_matches('-')) {
                output.push(format!("{name}=<redacted>"));
                redacted = true;
                continue;
            }
        }
        let (safe, changed) = redact_value(value);
        if safe.starts_with('-') && secret_name(safe.trim_start_matches('-')) {
            hide_next = true;
        }
        output.push(safe);
        redacted |= changed;
    }
    (output, redacted)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.bytes();
    matches!(chars.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && name.len() <= 128
        && chars.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_env(path: &Path, errors: &mut Errors) -> (Map<String, Value>, bool, bool, Vec<String>) {
    let raw = match limited(path, 256 * 1024) {
        Ok(raw) => raw,
        Err(error) => {
            report_io(errors, "environment", &error);
            return (
                Map::new(),
                false,
                false,
                vec!["environment_unreadable".to_owned()],
            );
        }
    };
    let mut redacted = false;
    let mut truncated = raw.len() > 256 * 1024;
    let mut missing = BTreeSet::new();
    let mut items = BTreeMap::new();
    for entry in raw[..raw.len().min(256 * 1024)].split(|byte| *byte == 0) {
        let Some(equal) = entry.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let name = String::from_utf8_lossy(&entry[..equal]).into_owned();
        if !valid_env_name(&name) {
            continue;
        }
        if secret_name(&name) {
            redacted = true;
            if missing.len() < 64 {
                missing.insert(name);
            }
            continue;
        }
        if !matches!(
            name.as_str(),
            "NODE_ENV" | "PORT" | "HOST" | "RUST_LOG" | "PYTHONPATH" | "VIRTUAL_ENV"
        ) && !name.starts_with("ABRA_RECIPE_")
        {
            continue;
        }
        let Ok(mut value) = String::from_utf8(entry[equal + 1..].to_vec()) else {
            truncated = true;
            continue;
        };
        if value.len() > 4096 {
            value = truncate_utf8(value, 4096);
            truncated = true;
        }
        let (value, changed) = redact_value(&value);
        redacted |= changed;
        if changed && missing.len() < 64 {
            missing.insert(name.clone());
        }
        items.insert(name, value);
    }
    let mut output = Map::new();
    let mut size = 0;
    for (name, value) in items {
        let item_size = name.len() + value.len();
        if output.len() >= 64 || size + item_size > 16 * 1024 {
            truncated = true;
            continue;
        }
        size += item_size;
        output.insert(name, Value::String(value));
    }
    (output, redacted, truncated, missing.into_iter().collect())
}

fn socket_map(proc_root: &Path, errors: &mut Errors) -> HashMap<String, BTreeSet<(String, u16)>> {
    let mut output: HashMap<String, BTreeSet<(String, u16)>> = HashMap::new();
    for (name, protocol, tcp) in [
        ("tcp", "tcp", true),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", false),
    ] {
        let input = match text(&proc_root.join("net").join(name)) {
            Ok(input) => input,
            Err(error) => {
                report_io(errors, "sockets", &error);
                continue;
            }
        };
        for line in input.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || (tcp && fields[3] != "0A") {
                continue;
            }
            let Some(port) = fields[1]
                .rsplit_once(':')
                .and_then(|part| u16::from_str_radix(part.1, 16).ok())
            else {
                continue;
            };
            if port != 0 {
                output
                    .entry(fields[9].to_owned())
                    .or_default()
                    .insert((protocol.to_owned(), port));
            }
        }
    }
    output
}

fn path_within(root: &Path, candidate: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

fn process_ports(
    base: &Path,
    inodes: &HashMap<String, BTreeSet<(String, u16)>>,
    errors: &mut Errors,
) -> (Vec<Value>, Vec<String>) {
    let mut found = BTreeSet::new();
    let mut external = BTreeSet::new();
    let entries = match fs::read_dir(base.join("fd")) {
        Ok(entries) => entries,
        Err(error) => {
            report_io(errors, "file_descriptors", &error);
            return (Vec::new(), Vec::new());
        }
    };
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            report(errors, "file_descriptors", "truncated");
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report_io(errors, "file_descriptors", &error);
                continue;
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) => {
                report_io(errors, "file_descriptors", &error);
                continue;
            }
        };
        let target = target.to_string_lossy();
        if target.starts_with('/') {
            if external.len() >= 64 {
                report(errors, "external_files", "truncated");
            } else {
                let (safe, changed) = redact_value(&target);
                if !changed && safe.len() <= 4096 {
                    external.insert(safe);
                }
            }
        }
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
        {
            if let Some(ports) = inodes.get(inode) {
                found.extend(ports.iter().cloned());
            }
        }
    }
    (
        found
            .into_iter()
            .map(|(protocol, port)| json!({"proto": protocol, "port": port}))
            .collect(),
        external.into_iter().collect(),
    )
}

fn username(path: &Path) -> Option<String> {
    let input = text(path).ok()?;
    let uid = input
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<libc::uid_t>()
        .ok()?;
    let mut record = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 4096];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status == 0 && !result.is_null() && !record.pw_name.is_null() {
        Some(
            unsafe { CStr::from_ptr(record.pw_name) }
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        Some(uid.to_string())
    }
}

fn process_metadata(proc_root: &Path, errors: &mut Errors) -> BTreeMap<i64, ProcessMeta> {
    let entries = match fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(error) => {
            report_io(errors, "processes", &error);
            return BTreeMap::new();
        }
    };
    let mut pids = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            report(errors, "processes", "unavailable");
            continue;
        };
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i64>().ok())
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    if pids.len() > 8192 {
        report(errors, "processes", "scan_truncated");
    }
    let mut output = BTreeMap::new();
    for pid in pids.into_iter().take(8192) {
        match parse_stat(&proc_root.join(pid.to_string()).join("stat")) {
            Ok(meta) => {
                output.insert(meta.pid, meta);
            }
            Err(error) => report_io(errors, "processes", &error),
        }
    }
    output
}

fn process_clock(proc_root: &Path) -> Option<(f64, i64)> {
    let uptime = text(&proc_root.join("uptime"))
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()?;
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (ticks > 0).then(|| {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        (epoch - uptime, ticks)
    })
}

fn resolve_process_cwd(path: &Path) -> io::Result<PathBuf> {
    let link = fs::read_link(path)?;
    if link.to_string_lossy().ends_with(" (deleted)") {
        return Err(io::Error::new(io::ErrorKind::NotFound, "deleted cwd"));
    }
    fs::canonicalize(link)
}

fn read_process(
    meta: &ProcessMeta,
    workspace: &Path,
    proc_root: &Path,
    inodes: &HashMap<String, BTreeSet<(String, u16)>>,
    clock: Option<(f64, i64)>,
    errors: &mut Errors,
) -> Option<Value> {
    let base = proc_root.join(meta.pid.to_string());
    let cwd = match resolve_process_cwd(&base.join("cwd")) {
        Ok(cwd) => cwd,
        Err(error) => {
            report_io(errors, "process_details", &error);
            return None;
        }
    };
    let inside = path_within(workspace, &cwd);
    let raw = match limited(&base.join("cmdline"), 64 * 1024) {
        Ok(raw) => raw,
        Err(error) => {
            report_io(errors, "process_details", &error);
            return None;
        }
    };
    if raw.is_empty() {
        return None;
    }
    let mut truncated = raw.len() > 64 * 1024;
    let bounded = &raw[..raw.len().min(64 * 1024)];
    let mut argv = Vec::new();
    for item in bounded
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
    {
        let Ok(mut argument) = String::from_utf8(item.to_vec()) else {
            argv = vec!["<omitted: non-UTF8 command>".to_owned()];
            truncated = true;
            break;
        };
        if argument.len() > 4096 {
            argument = "<omitted: argument exceeds limit>".to_owned();
            truncated = true;
        }
        argv.push(argument);
        if argv.len() == 256 {
            if bounded
                .split(|byte| *byte == 0)
                .filter(|item| !item.is_empty())
                .count()
                > 256
            {
                truncated = true;
            }
            break;
        }
    }
    if argv.is_empty() {
        return None;
    }
    let (argv, argv_redacted) = redact_argv(&argv);
    let (environment, env_redacted, env_truncated, missing) =
        parse_env(&base.join("environ"), errors);
    truncated |= env_truncated;
    let relative = inside
        .then(|| cwd.strip_prefix(workspace).unwrap_or(Path::new("")))
        .map(|path| {
            if path.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                path.to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/")
            }
        });
    let mut row = Map::new();
    row.insert("pid".to_owned(), json!(meta.pid));
    row.insert("ppid".to_owned(), json!(meta.ppid));
    row.insert("start_ticks".to_owned(), json!(meta.start));
    row.insert("argv".to_owned(), json!(argv));
    row.insert(
        "cwd".to_owned(),
        relative.map(Value::String).unwrap_or(Value::Null),
    );
    row.insert(
        "workspace_relation".to_owned(),
        json!(if inside { "inside" } else { "outside" }),
    );
    row.insert("state".to_owned(), json!(meta.state));
    if !inside {
        let (safe, _) = redact_value(&cwd.to_string_lossy());
        row.insert("external_cwd".to_owned(), json!(truncate_utf8(safe, 4096)));
    }
    if !missing.is_empty() {
        row.insert("missing_environment".to_owned(), json!(missing));
    }
    if let Ok(exe) = fs::read_link(base.join("exe")) {
        let (safe, _) = redact_value(&exe.to_string_lossy());
        row.insert("exe".to_owned(), json!(truncate_utf8(safe, 4096)));
    }
    if let Some(user) = username(&base.join("status")) {
        row.insert("user".to_owned(), json!(user));
    }
    if !environment.is_empty() {
        row.insert("env".to_owned(), Value::Object(environment));
    }
    let (ports, external) = process_ports(&base, inodes, errors);
    let external: Vec<String> = external
        .into_iter()
        .filter(|path| !path_within(workspace, Path::new(path)))
        .collect();
    if !external.is_empty() {
        row.insert("external_open_files".to_owned(), json!(external));
    }
    if !ports.is_empty() {
        row.insert("ports".to_owned(), Value::Array(ports));
    }
    if let Some((boot, ticks)) = clock {
        let seconds = boot + meta.start as f64 / ticks as f64;
        if seconds.is_finite() && seconds >= 0.0 {
            row.insert(
                "started_at".to_owned(),
                json!(canonical_time(
                    UNIX_EPOCH + Duration::from_secs_f64(seconds)
                )),
            );
        }
    }
    if argv_redacted || env_redacted {
        row.insert("redacted".to_owned(), Value::Bool(true));
    }
    if truncated {
        row.insert("truncated".to_owned(), Value::Bool(true));
    }
    match parse_stat(&base.join("stat")) {
        Ok(after) if after.start == meta.start => Some(Value::Object(row)),
        Ok(_) => {
            report(errors, "processes", "pid_reused");
            None
        }
        Err(error) => {
            report_io(errors, "processes", &error);
            None
        }
    }
}

fn truncate_utf8(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn cgroup_matches(value: &str, wanted: &str) -> bool {
    value == wanted
        || value
            .strip_prefix(wanted.trim_end_matches('/'))
            .is_some_and(|rest| rest.starts_with('/'))
}

fn scan_processes(args: &ObserveArgs, errors: &mut Errors) -> Vec<Value> {
    let metadata = process_metadata(&args.r#proc, errors);
    let inodes = socket_map(&args.r#proc, errors);
    let workspace = match fs::canonicalize(&args.workspace) {
        Ok(path) => path,
        Err(error) => {
            report_io(errors, "membership", &error);
            args.workspace.clone()
        }
    };
    let clock = process_clock(&args.r#proc);
    let self_pid = std::process::id() as i64;
    let mut selected: BTreeMap<i64, &'static str> = BTreeMap::new();
    for (pid, meta) in &metadata {
        if *pid == self_pid {
            continue;
        }
        let membership = if args.all {
            Some("all")
        } else if let Some(cgroup) = args.cgroup.as_deref() {
            match text(&args.r#proc.join(pid.to_string()).join("cgroup")) {
                Ok(input) => input
                    .lines()
                    .filter_map(|line| line.strip_prefix("0::"))
                    .any(|value| cgroup_matches(value, cgroup))
                    .then_some("cgroup"),
                Err(error) => {
                    report_io(errors, "membership", &error);
                    None
                }
            }
        } else if args
            .process_group
            .is_some_and(|group| meta.group == group as i64)
        {
            Some("process_group")
        } else if args.process_group.is_some() {
            None
        } else {
            match resolve_process_cwd(&args.r#proc.join(pid.to_string()).join("cwd")) {
                Ok(cwd) => path_within(&workspace, &cwd).then_some("workspace"),
                Err(error) => {
                    report_io(errors, "membership", &error);
                    None
                }
            }
        };
        if let Some(membership) = membership {
            selected.insert(*pid, membership);
        }
    }
    loop {
        let additions: Vec<i64> = metadata
            .iter()
            .filter(|(pid, meta)| {
                **pid != self_pid
                    && !selected.contains_key(pid)
                    && selected.contains_key(&meta.ppid)
            })
            .map(|(pid, _)| *pid)
            .collect();
        if additions.is_empty() {
            break;
        }
        for pid in additions {
            selected.insert(pid, "descendant");
        }
    }
    let network_namespace = match fs::read_link(args.r#proc.join("self/ns/net")) {
        Ok(namespace) => Some(namespace),
        Err(_) => {
            report(errors, "network_namespaces", "unavailable");
            None
        }
    };
    if selected.len() > 1024 {
        report(errors, "processes", "details_truncated");
    }
    let mut output = Vec::new();
    for (pid, membership) in selected.into_iter().take(1024) {
        let Some(meta) = metadata.get(&pid) else {
            continue;
        };
        let Some(mut row) = read_process(meta, &workspace, &args.r#proc, &inodes, clock, errors)
        else {
            continue;
        };
        row["membership"] = json!(membership);
        match fs::read_link(args.r#proc.join(pid.to_string()).join("ns/net")) {
            Ok(namespace) if Some(&namespace) == network_namespace.as_ref() => {}
            Ok(_) => {
                row.as_object_mut().unwrap().remove("ports");
                report(errors, "network_namespaces", "unsupported_namespace");
            }
            Err(_) => {
                row.as_object_mut().unwrap().remove("ports");
                report(errors, "network_namespaces", "unavailable");
            }
        }
        output.push(row);
    }
    output
}

fn command_name(row: &Value) -> String {
    let argv = row["argv"].as_array().cloned().unwrap_or_default();
    let first = argv
        .first()
        .and_then(Value::as_str)
        .map(basename)
        .unwrap_or("");
    if INTERPRETERS.contains(&first) {
        if let Some(next) = argv
            .get(1)
            .and_then(Value::as_str)
            .filter(|next| !next.starts_with('-'))
        {
            return basename(next).to_owned();
        }
    }
    first.to_owned()
}

fn interactive(row: &Value) -> bool {
    SHELLS.contains(&command_name(row).as_str())
        && !row["argv"]
            .as_array()
            .into_iter()
            .flatten()
            .skip(1)
            .filter_map(Value::as_str)
            .any(|value| value.starts_with('-') && value[1..].contains('c'))
}

fn derive_services(processes: &[Value]) -> Vec<Value> {
    let by_pid: HashMap<i64, &Value> = processes
        .iter()
        .filter_map(|row| row["pid"].as_i64().map(|pid| (pid, row)))
        .collect();
    let mut groups: BTreeMap<i64, (&Value, Vec<&Value>)> = BTreeMap::new();
    for row in processes {
        if interactive(row) {
            continue;
        }
        let mut root = row;
        let mut seen = HashSet::from([root["pid"].as_i64().unwrap_or(-1)]);
        loop {
            let Some(parent) = root["ppid"]
                .as_i64()
                .and_then(|pid| by_pid.get(&pid).copied())
            else {
                break;
            };
            let parent_pid = parent["pid"].as_i64().unwrap_or(-1);
            if seen.contains(&parent_pid)
                || interactive(parent)
                || matches!(command_name(parent).as_str(), "codex" | "claude" | "agent")
                || (parent_pid == 1 && parent["cwd"].is_null())
            {
                break;
            }
            seen.insert(parent_pid);
            root = parent;
        }
        let root_pid = root["pid"].as_i64().unwrap_or(-1);
        groups
            .entry(root_pid)
            .or_insert((root, Vec::new()))
            .1
            .push(row);
    }
    let mut output = Vec::new();
    for (root_pid, (root, members)) in groups {
        let mut missing = BTreeSet::new();
        let mut source_pids = Vec::new();
        let mut external_files = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for row in &members {
            source_pids.push(row["pid"].as_i64().unwrap_or(-1));
            if row.get("redacted").and_then(Value::as_bool) == Some(true) {
                missing.insert("redacted_arguments_or_environment".to_owned());
            }
            if row.get("truncated").and_then(Value::as_bool) == Some(true) {
                missing.insert("truncated_process_data".to_owned());
            }
            if row["cwd"].is_null() {
                missing.insert("working_directory_outside_workspace".to_owned());
            }
            for name in row
                .get("missing_environment")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                missing.insert(format!("environment:{name}"));
            }
            for path in row
                .get("external_open_files")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                external_files.insert(path.to_owned());
            }
            for port in row
                .get("ports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|port| port["proto"] == "tcp")
                .filter_map(|port| port["port"].as_u64())
            {
                ports.insert(port);
            }
        }
        source_pids.sort_unstable();
        let mut recipe = Map::new();
        recipe.insert("argv".to_owned(), root["argv"].clone());
        recipe.insert("cwd".to_owned(), root["cwd"].clone());
        for key in ["env", "started_at"] {
            if let Some(value) = root.get(key) {
                recipe.insert(key.to_owned(), value.clone());
            }
        }
        if !ports.is_empty() {
            recipe.insert("ports".to_owned(), json!(ports));
        }
        let has_ports = !ports.is_empty();
        let external_files: Vec<String> = external_files.into_iter().take(64).collect();
        output.push(json!({
            "source": "process-tree-inference",
            "source_pids": source_pids,
            "root_pid": root_pid,
            "recipe": recipe,
            "restartability": if missing.is_empty() { "unverified" } else { "blocked" },
            "missing_requirements": missing,
            "reasons": [if has_ports { "listening_socket" } else { "observed_process" }, "children_grouped_with_parent"],
            "requires_adapter_confirmation": true,
            "requirements": {
                "executable": root.get("exe").cloned().unwrap_or(Value::Null),
                "external_files": external_files,
                "runtime_verification": "required"
            }
        }));
    }
    output.sort_by_key(|candidate| {
        (
            candidate["recipe"].get("ports").is_none(),
            candidate["root_pid"].as_i64().unwrap_or(i64::MAX),
        )
    });
    output
}

fn platform_info(proc_root: &Path) -> Value {
    let mut uname = unsafe { std::mem::zeroed::<libc::utsname>() };
    let mut output = Map::new();
    if unsafe { libc::uname(&mut uname) } == 0 {
        let field = |bytes: &[libc::c_char]| {
            unsafe { CStr::from_ptr(bytes.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        output.insert(
            "os".to_owned(),
            json!(field(&uname.sysname).to_ascii_lowercase()),
        );
        output.insert("arch".to_owned(), json!(field(&uname.machine)));
        output.insert("kernel".to_owned(), json!(field(&uname.release)));
        let hostname = field(&uname.nodename);
        if !hostname.is_empty() {
            output.insert(
                "hostname".to_owned(),
                json!(truncate_utf8(redact_value(&hostname).0, 128)),
            );
        }
    } else {
        output.insert("os".to_owned(), json!(std::env::consts::OS));
        output.insert("arch".to_owned(), json!(std::env::consts::ARCH));
    }
    if let Ok(boot_id) = text(&proc_root.join("sys/kernel/random/boot_id")) {
        output.insert("boot_id".to_owned(), json!(boot_id.trim()));
    }
    let mut release = Map::new();
    if let Ok(input) = text(Path::new("/etc/os-release")) {
        for line in input.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.to_ascii_lowercase();
                if matches!(key.as_str(), "id" | "version_id") {
                    release.insert(key, json!(value.trim_matches(['\"', '\''])));
                }
            }
        }
    }
    if !release.is_empty() {
        output.insert("os_release".to_owned(), Value::Object(release));
    }
    if let Ok(image) = text(Path::new("/etc/abra/image-id")) {
        let image = image.trim();
        if !image.is_empty() && image.len() <= 128 {
            output.insert("image_id".to_owned(), json!(redact_value(image).0));
        }
    }
    Value::Object(output)
}

fn cpu_count() -> Option<usize> {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    (count > 0).then_some(count as usize)
}

#[cfg(target_os = "linux")]
fn affinity_count() -> Option<usize> {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } != 0
    {
        return None;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&set as *const libc::cpu_set_t).cast::<u8>(),
            std::mem::size_of::<libc::cpu_set_t>(),
        )
    };
    Some(bytes.iter().map(|byte| byte.count_ones() as usize).sum())
}

#[cfg(not(target_os = "linux"))]
fn affinity_count() -> Option<usize> {
    cpu_count()
}

fn cpuset_count(value: &str) -> Option<u64> {
    let mut count = 0_u64;
    for part in value.split(',') {
        let mut ends = part.split('-');
        let start = ends.next()?.parse::<u64>().ok()?;
        let end = ends.next().unwrap_or(part).parse::<u64>().ok()?;
        count = count.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
    }
    Some(count)
}

fn safe_cgroup_dir(root: &Path, cgroup: &str) -> io::Result<PathBuf> {
    if !cgroup.starts_with('/')
        || Path::new(cgroup)
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup escapes root",
        ));
    }
    let root = fs::canonicalize(root)?;
    let directory = fs::canonicalize(root.join(cgroup.trim_start_matches('/')))?;
    if !path_within(&root, &directory) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup escapes root",
        ));
    }
    Ok(directory)
}

fn resource_info(args: &ObserveArgs, errors: &mut Errors) -> Value {
    let mut output = Map::from_iter([("source".to_owned(), json!("guest-os"))]);
    match text(&args.r#proc.join("meminfo")) {
        Ok(input) => {
            if let Some(memory) = input.lines().find(|line| line.starts_with("MemTotal:")) {
                if let Some(kib) = memory
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    output.insert("memory_mb".to_owned(), json!(kib / 1024));
                }
            }
        }
        Err(error) => report_io(errors, "resources", &error),
    }
    if let Some(cpus) = cpu_count() {
        output.insert("cpus".to_owned(), json!(cpus));
    }
    if let Some(cpus) = affinity_count().or_else(cpu_count) {
        output.insert("affinity_cpus".to_owned(), json!(cpus));
    }
    let cgroup = match args.cgroup.clone() {
        Some(cgroup) => Some(cgroup),
        None => match text(&args.r#proc.join("self/cgroup")) {
            Ok(input) => input
                .lines()
                .find_map(|line| line.strip_prefix("0::").map(str::to_owned)),
            Err(error) => {
                report_io(errors, "cgroup_limits", &error);
                None
            }
        },
    };
    if let Some(cgroup) = cgroup {
        match safe_cgroup_dir(&args.cgroup_root, &cgroup) {
            Ok(mut directory) => {
                let root = fs::canonicalize(&args.cgroup_root)
                    .unwrap_or_else(|_| args.cgroup_root.clone());
                let mut memory = output["memory_mb"]
                    .as_u64()
                    .and_then(|mb| mb.checked_mul(1024 * 1024));
                let mut cpu_millicores = output["affinity_cpus"]
                    .as_u64()
                    .and_then(|cpus| cpus.checked_mul(1000));
                loop {
                    match text(&directory.join("memory.max")) {
                        Ok(value) if value.trim() != "max" => match value.trim().parse::<u64>() {
                            Ok(value) => memory = Some(memory.map_or(value, |old| old.min(value))),
                            Err(_) => report(errors, "cgroup_limits", "unavailable"),
                        },
                        Ok(_) => {}
                        Err(error) => report_io(errors, "cgroup_limits", &error),
                    }
                    match text(&directory.join("cpu.max")) {
                        Ok(value) => {
                            let fields: Vec<&str> = value.split_whitespace().collect();
                            if fields.len() == 2 && fields[0] != "max" {
                                match (fields[0].parse::<u64>(), fields[1].parse::<u64>()) {
                                    (Ok(quota), Ok(period)) if period != 0 => {
                                        let value = quota.saturating_mul(1000) / period;
                                        cpu_millicores = Some(
                                            cpu_millicores.map_or(value, |old| old.min(value)),
                                        );
                                    }
                                    _ => report(errors, "cgroup_limits", "unavailable"),
                                }
                            }
                        }
                        Err(error) => report_io(errors, "cgroup_limits", &error),
                    }
                    match text(&directory.join("cpuset.cpus.effective")) {
                        Ok(value) if !value.trim().is_empty() => match cpuset_count(value.trim()) {
                            Some(cpus) => {
                                let value = cpus.saturating_mul(1000);
                                cpu_millicores =
                                    Some(cpu_millicores.map_or(value, |old| old.min(value)));
                            }
                            None => report(errors, "cgroup_limits", "unavailable"),
                        },
                        Ok(_) => {}
                        Err(error) => report_io(errors, "cgroup_limits", &error),
                    }
                    if directory == root {
                        break;
                    }
                    let Some(parent) = directory.parent() else {
                        break;
                    };
                    directory = parent.to_owned();
                }
                if let Some(memory) = memory {
                    output.insert("effective_memory_bytes".to_owned(), json!(memory));
                }
                if let Some(cpu) = cpu_millicores {
                    output.insert("effective_cpu_millicores".to_owned(), json!(cpu));
                }
                output.insert("cgroup".to_owned(), json!(cgroup));
            }
            Err(error) => report_io(errors, "cgroup_limits", &error),
        }
    }
    Value::Object(output)
}

fn executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn probe_one(path: &Path, runtime_path: &OsStr) -> io::Result<Option<String>> {
    let mut command = Command::new(path);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", runtime_path);
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let fd = stdout.as_raw_fd();
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if descriptor_flags < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFL, descriptor_flags | libc::O_NONBLOCK) } < 0
    {
        let error = io::Error::last_os_error();
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.wait();
        return Err(error);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut data = Vec::new();
    while data.len() < 4096 && Instant::now() < deadline {
        let mut buffer = [0_u8; 512];
        let read_limit = buffer.len().min(4096 - data.len());
        match stdout.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(count) => {
                data.extend_from_slice(&buffer[..count]);
                if data.contains(&b'\n') {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.wait();
                return Err(error);
            }
        }
    }
    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.wait();
    if data.is_empty() {
        return Ok(None);
    }
    let first = String::from_utf8_lossy(&data)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    let (safe, changed) = redact_value(&first);
    Ok((!safe.is_empty() && !changed).then(|| truncate_utf8(safe, 64)))
}

fn probe_runtimes(dirs: &[PathBuf], errors: &mut Errors) -> Value {
    let runtime_path = std::env::join_paths(dirs).unwrap_or_default();
    let mut output = Map::new();
    for name in RUNTIMES {
        for directory in dirs {
            let path = directory.join(name);
            if !executable(&path) {
                continue;
            }
            match probe_one(&path, &runtime_path) {
                Ok(Some(version)) => {
                    output.insert((*name).to_owned(), json!(version));
                }
                Ok(None) => report(errors, "runtimes", "probe_failed_or_timed_out"),
                Err(error) => report_io(errors, "runtimes", &error),
            }
            break;
        }
    }
    Value::Object(output)
}

fn unescape_mount(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4]
                .iter()
                .all(|b| matches!(b, b'0'..=b'7'))
        {
            let number =
                (bytes[index + 1] - b'0') * 64 + (bytes[index + 2] - b'0') * 8 + bytes[index + 3]
                    - b'0';
            output.push(number);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn mount_info(args: &ObserveArgs, errors: &mut Errors) -> Vec<Value> {
    let workspace = fs::canonicalize(&args.workspace).unwrap_or_else(|_| args.workspace.clone());
    let input = match text(&args.r#proc.join("self/mountinfo")) {
        Ok(input) => input,
        Err(error) => {
            report_io(errors, "mounts", &error);
            return Vec::new();
        }
    };
    let mut output = Vec::new();
    for line in input.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(split) = fields.iter().position(|field| *field == "-") else {
            report(errors, "mounts", "malformed_record");
            continue;
        };
        if fields.len() <= split + 2 || fields.len() <= 5 {
            report(errors, "mounts", "malformed_record");
            continue;
        }
        let target = unescape_mount(fields[4]);
        let target_path = Path::new(&target);
        let relative = target_path.strip_prefix(&workspace).ok();
        let inside = path_within(&workspace, target_path)
            && !relative
                .into_iter()
                .flat_map(Path::components)
                .any(|component| component.as_os_str() == ".abra");
        output.push(json!({
            "target": truncate_utf8(redact_value(&target).0, 4096),
            "fstype": fields[split + 1],
            "source": truncate_utf8(redact_value(fields[split + 2]).0, 4096),
            "mutable": fields[5].split(',').any(|option| option == "rw"),
            "capture": if inside { "workspace-file-tree" } else { "not-captured" },
            "contents_verified": false
        }));
        if output.len() >= 64 {
            report(errors, "mounts", "truncated");
            break;
        }
    }
    output
}

fn runtime_dirs(args: &ObserveArgs) -> Vec<PathBuf> {
    std::env::split_paths(OsStr::new(&args.runtime_dirs)).collect()
}

fn collect_environment(args: &ObserveArgs) -> Value {
    let mut errors = Vec::new();
    json!({
        "platform": platform_info(&args.r#proc),
        "runtimes": probe_runtimes(&runtime_dirs(args), &mut errors),
        "source": "guest-os",
        "observed_at": now(),
        "collection_errors": errors
    })
}

fn capture(args: &ObserveArgs, environment: &Value) -> Result<Value, Box<dyn Error>> {
    let started = now();
    let mut errors = Vec::new();
    let mut processes = scan_processes(args, &mut errors);
    processes.sort_by_key(|row| {
        (
            row.get("ports").is_none(),
            row.get("started_at")
                .and_then(Value::as_str)
                .unwrap_or("9999")
                .to_owned(),
            row["pid"].as_i64().unwrap_or(i64::MAX),
        )
    });
    let mut services = derive_services(&processes);
    let processes_dropped = processes.len().saturating_sub(512);
    processes.truncate(512);
    let services_dropped = services.len().saturating_sub(256);
    services.truncate(256);
    let resources = resource_info(args, &mut errors);
    let mounts = mount_info(args, &mut errors);
    if let Some(environment_errors) = environment["collection_errors"].as_array() {
        for error in environment_errors {
            if let (Some(collector), Some(code), Some(count)) = (
                error["collector"].as_str(),
                error["code"].as_str(),
                error["count"].as_u64(),
            ) {
                for _ in 0..count {
                    report(&mut errors, collector, code);
                }
            }
        }
    }
    let finished = now();
    let mut observer = Map::from_iter([
        ("version".to_owned(), json!(3)),
        ("observed_at".to_owned(), json!(finished)),
        ("capture_started_at".to_owned(), json!(started)),
        ("capture_finished_at".to_owned(), json!(finished)),
        (
            "mode".to_owned(),
            json!(if args.once { "once" } else { "periodic" }),
        ),
        (
            "environment_observed_at".to_owned(),
            environment["observed_at"].clone(),
        ),
        (
            "environment_refresh_interval_ms".to_owned(),
            json!((args.environment_interval * 1000.0) as u64),
        ),
    ]);
    if args.once {
        if let Some(barrier) = &args.barrier {
            observer.insert("barrier".to_owned(), json!(barrier));
        }
    } else {
        observer.insert(
            "interval_ms".to_owned(),
            json!((args.interval * 1000.0) as u64),
        );
    }
    let recipes: Vec<Value> = services
        .iter()
        .filter(|candidate| candidate["restartability"] == "unverified")
        .map(|candidate| candidate["recipe"].clone())
        .collect();
    let scope = if args.all {
        "all"
    } else if args.cgroup.is_some() {
        "cgroup"
    } else if args.process_group.is_some() {
        "process_group"
    } else {
        "workspace-and-descendants"
    };
    let mut ledger = json!({
        "schema": SCHEMA,
        "observer": observer,
        "platform": environment["platform"].clone(),
        "resources": resources,
        "runtimes": environment["runtimes"].clone(),
        "processes": processes,
        "service_candidates": services,
        "recipes": recipes,
        "mounts": mounts,
        "collection_errors": errors,
        "coverage": {
            "complete": false,
            "scope": scope,
            "consistency": "best-effort",
            "applications_quiesced": false,
            "limitations": LIMITATIONS
        },
        "limits": {
            "processes_dropped": processes_dropped,
            "services_dropped": services_dropped
        }
    });
    enforce_size_limit(&mut ledger)?;
    Ok(ledger)
}

fn encoded_ledger(ledger: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(ledger)
}

fn enforce_size_limit(ledger: &mut Value) -> Result<(), Box<dyn Error>> {
    for (field, counter) in [
        ("processes", "processes_dropped"),
        ("service_candidates", "services_dropped"),
    ] {
        while encoded_ledger(ledger)?.len() > MAX_FILE
            && !ledger[field].as_array().unwrap().is_empty()
        {
            let length = ledger[field].as_array().unwrap().len();
            let count = (length / 2).max(1);
            ledger[field]
                .as_array_mut()
                .unwrap()
                .truncate(length - count);
            let old = ledger["limits"][counter].as_u64().unwrap_or(0);
            ledger["limits"][counter] = json!(old + count as u64);
            if field == "service_candidates" {
                ledger["recipes"] = Value::Array(
                    ledger[field]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|candidate| candidate["restartability"] == "unverified")
                        .map(|candidate| candidate["recipe"].clone())
                        .collect(),
                );
            }
        }
    }
    if encoded_ledger(ledger)?.len() > MAX_FILE {
        return Err(invalid(
            "observed ledger exceeds 240 KiB after dropping process and service records",
        ));
    }
    Ok(())
}

fn capture_filename(barrier: Option<&str>) -> Result<String, Box<dyn Error>> {
    match barrier {
        None => Ok("observed.json".to_owned()),
        Some(barrier) if valid_barrier(barrier) => Ok(format!("observed-{barrier}.json")),
        Some(_) => Err(invalid(
            "barrier must be 1 to 64 ASCII letters, digits, underscores or hyphens",
        )),
    }
}

fn valid_barrier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let path = cstring(path.as_os_str())?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn random_temp_name() -> io::Result<String> {
    let mut bytes = [0_u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        ".observed.json.{}.{suffix}.tmp",
        std::process::id()
    ))
}

fn write_ledger(args: &ObserveArgs, ledger: &Value) -> Result<String, Box<dyn Error>> {
    let filename = capture_filename(args.once.then_some(args.barrier.as_deref()).flatten())?;
    let workspace = open_directory(&args.workspace)?;
    let metadata_name = cstring(OsStr::new(".abra"))?;
    if unsafe { libc::mkdirat(workspace.as_raw_fd(), metadata_name.as_ptr(), 0o700) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(Box::new(error));
        }
    }
    let metadata_fd = unsafe {
        libc::openat(
            workspace.as_raw_fd(),
            metadata_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if metadata_fd < 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let metadata = unsafe { OwnedFd::from_raw_fd(metadata_fd) };
    if unsafe { libc::fchmod(metadata.as_raw_fd(), 0o700) } != 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let mut temp_name = None;
    let mut temp_file = None;
    for _ in 0..16 {
        let candidate = random_temp_name()?;
        let c_candidate = cstring(OsStr::new(&candidate))?;
        let fd = unsafe {
            libc::openat(
                metadata.as_raw_fd(),
                c_candidate.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            temp_name = Some(candidate);
            temp_file = Some(unsafe { File::from_raw_fd(fd) });
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(Box::new(error));
        }
    }
    let temp_name = temp_name.ok_or_else(|| invalid("could not allocate observation temp file"))?;
    let mut temp_file = temp_file.expect("temp name and file are paired");
    let cleanup_name = cstring(OsStr::new(&temp_name))?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        temp_file.write_all(&encoded_ledger(ledger)?)?;
        temp_file.sync_all()?;
        drop(temp_file);
        let destination = cstring(OsStr::new(&filename))?;
        if args.once && args.barrier.is_some() {
            if unsafe {
                libc::linkat(
                    metadata.as_raw_fd(),
                    cleanup_name.as_ptr(),
                    metadata.as_raw_fd(),
                    destination.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(Box::new(io::Error::last_os_error()));
            }
            if unsafe { libc::unlinkat(metadata.as_raw_fd(), cleanup_name.as_ptr(), 0) } != 0 {
                return Err(Box::new(io::Error::last_os_error()));
            }
        } else if unsafe {
            libc::renameat(
                metadata.as_raw_fd(),
                cleanup_name.as_ptr(),
                metadata.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(Box::new(io::Error::last_os_error()));
        }
        if args.once && unsafe { libc::fsync(metadata.as_raw_fd()) } != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(metadata.as_raw_fd(), cleanup_name.as_ptr(), 0) };
    }
    result?;
    Ok(filename)
}

fn validate(args: &ObserveArgs) -> Result<(), Box<dyn Error>> {
    for value in [args.interval, args.environment_interval] {
        if !value.is_finite() || !(0.001..=86400.0).contains(&value) {
            return Err(invalid("intervals must be between 0.001 and 86400 seconds"));
        }
    }
    if args
        .barrier
        .as_deref()
        .is_some_and(|barrier| !valid_barrier(barrier))
        || (args.barrier.is_some() && !args.once)
    {
        return Err(invalid(
            "--barrier requires --once and 1 to 64 ASCII letters, digits, underscores or hyphens",
        ));
    }
    if args.process_group.is_some_and(|group| group <= 0) {
        return Err(invalid("--process-group must be positive"));
    }
    if let Some(cgroup) = &args.cgroup {
        if !cgroup.starts_with('/')
            || Path::new(cgroup)
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(invalid(
                "--cgroup must be an absolute cgroup path without '..'",
            ));
        }
    }
    if usize::from(args.all)
        + usize::from(args.cgroup.is_some())
        + usize::from(args.process_group.is_some())
        > 1
    {
        return Err(invalid(
            "--all, --cgroup, and --process-group are mutually exclusive",
        ));
    }
    Ok(())
}

pub fn run(args: ObserveArgs) -> Result<Value, Box<dyn Error>> {
    validate(&args)?;
    unsafe { libc::umask(0o077) };
    let mut environment = collect_environment(&args);
    if args.once {
        let ledger = capture(&args, &environment)?;
        let filename = write_ledger(&args, &ledger)?;
        let mut summary = json!({
            "filename": filename,
            "observed_at": ledger["observer"]["observed_at"],
            "processes": ledger["processes"].as_array().map_or(0, Vec::len),
            "recipes": ledger["recipes"].as_array().map_or(0, Vec::len)
        });
        if let Some(barrier) = args.barrier {
            summary["barrier"] = json!(barrier);
        }
        return Ok(summary);
    }
    let mut refreshed = Instant::now();
    loop {
        if refreshed.elapsed() >= Duration::from_secs_f64(args.environment_interval) {
            environment = collect_environment(&args);
            refreshed = Instant::now();
        }
        match capture(&args, &environment)
            .and_then(|ledger| write_ledger(&args, &ledger).map(|_| ledger))
        {
            Ok(_) => {}
            Err(error) => eprintln!("abra-observer: {error}"),
        }
        std::thread::sleep(Duration::from_secs_f64(args.interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        temp: tempfile::TempDir,
        workspace: PathBuf,
        proc_root: PathBuf,
        runtime: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let workspace = temp.path().join("workspace");
            let proc_root = temp.path().join("proc");
            let runtime = temp.path().join("bin");
            fs::create_dir(&workspace).unwrap();
            fs::create_dir_all(proc_root.join("net")).unwrap();
            fs::create_dir_all(proc_root.join("self/ns")).unwrap();
            fs::create_dir(&runtime).unwrap();
            symlink("net:[1]", proc_root.join("self/ns/net")).unwrap();
            fs::write(proc_root.join("uptime"), "100.0 0.0\n").unwrap();
            fs::write(proc_root.join("meminfo"), "MemTotal: 524288 kB\n").unwrap();
            fs::write(proc_root.join("self/mountinfo"), "").unwrap();
            let header = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
            for name in ["tcp", "tcp6", "udp", "udp6"] {
                fs::write(proc_root.join("net").join(name), header).unwrap();
            }
            Self {
                temp,
                workspace,
                proc_root,
                runtime,
            }
        }

        fn args(&self) -> ObserveArgs {
            ObserveArgs {
                workspace: self.workspace.clone(),
                once: true,
                barrier: None,
                r#proc: self.proc_root.clone(),
                all: false,
                cgroup: None,
                process_group: None,
                interval: 2.0,
                environment_interval: 300.0,
                runtime_dirs: self.runtime.to_string_lossy().into_owned(),
                cgroup_root: self.temp.path().join("cgroup"),
            }
        }

        fn add_process(
            &self,
            pid: i64,
            ppid: i64,
            argv: &[&str],
            cwd: Option<&Path>,
            env: &[(&str, &str)],
            ports: &[(&str, u16, &str)],
        ) {
            let base = self.proc_root.join(pid.to_string());
            fs::create_dir_all(base.join("fd")).unwrap();
            fs::create_dir(base.join("ns")).unwrap();
            symlink("net:[1]", base.join("ns/net")).unwrap();
            let mut command = argv.join("\0").into_bytes();
            command.push(0);
            fs::write(base.join("cmdline"), command).unwrap();
            let mut environment = env
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("\0")
                .into_bytes();
            environment.push(0);
            fs::write(base.join("environ"), environment).unwrap();
            let fields = std::iter::once("S".to_owned())
                .chain(std::iter::once(ppid.to_string()))
                .chain((0..17).map(|_| "0".to_owned()))
                .chain(std::iter::once((pid * 10).to_string()))
                .collect::<Vec<_>>();
            fs::write(
                base.join("stat"),
                format!("{pid} (process {pid}) {}\n", fields.join(" ")),
            )
            .unwrap();
            fs::write(
                base.join("status"),
                format!(
                    "Uid:\t{}\t{}\t{}\t{}\n",
                    unsafe { libc::getuid() },
                    unsafe { libc::getuid() },
                    unsafe { libc::getuid() },
                    unsafe { libc::getuid() }
                ),
            )
            .unwrap();
            symlink(cwd.unwrap_or(&self.workspace), base.join("cwd")).unwrap();
            symlink(format!("/usr/bin/{}", basename(argv[0])), base.join("exe")).unwrap();
            for (index, (protocol, port, inode)) in ports.iter().enumerate() {
                symlink(
                    format!("socket:[{inode}]"),
                    base.join("fd").join(index.to_string()),
                )
                .unwrap();
                let table = self.proc_root.join("net").join(protocol);
                let mut handle = fs::OpenOptions::new().append(true).open(table).unwrap();
                let state = if protocol.starts_with("tcp") {
                    "0A"
                } else {
                    "07"
                };
                writeln!(
                    handle,
                    "0: 00000000:{port:04X} 00000000:0000 {state} 0 0 0 0 0 {inode}"
                )
                .unwrap();
            }
        }

        fn environment(&self) -> Value {
            json!({
                "platform": {"arch": "fixture"},
                "runtimes": {},
                "observed_at": "2020-01-01T00:00:00.000Z",
                "collection_errors": []
            })
        }
    }

    #[test]
    fn process_tree_ports_and_redaction_match_schema_three() {
        let fixture = Fixture::new();
        fixture.add_process(10, 1, &["npm", "run", "dev"], None, &[], &[]);
        fixture.add_process(11, 10, &["sh", "-c", "node server.js"], None, &[], &[]);
        fixture.add_process(
            12,
            11,
            &["node", "server.js", "--token", "actualsecret"],
            None,
            &[
                ("DATABASE_PASSWORD", "alsosecret"),
                ("NODE_ENV", "development"),
            ],
            &[("tcp", 5173, "100"), ("udp", 5353, "101")],
        );
        let ledger = capture(&fixture.args(), &fixture.environment()).unwrap();
        assert_eq!(ledger["schema"], SCHEMA);
        assert!(!serde_json::to_string(&ledger)
            .unwrap()
            .contains("actualsecret"));
        assert!(!serde_json::to_string(&ledger)
            .unwrap()
            .contains("alsosecret"));
        assert_eq!(
            ledger["processes"][0]["ports"][0],
            json!({"proto":"tcp", "port":5173})
        );
        assert_eq!(
            ledger["processes"][0]["ports"][1],
            json!({"proto":"udp", "port":5353})
        );
        assert_eq!(ledger["service_candidates"][0]["restartability"], "blocked");
        assert_eq!(ledger["recipes"], json!([]));
    }

    #[test]
    fn cgroup_selection_includes_descendants_and_rejects_similar_sibling() {
        let fixture = Fixture::new();
        fixture.add_process(90, 1, &["server"], Some(fixture.temp.path()), &[], &[]);
        fixture.add_process(91, 90, &["worker"], Some(fixture.temp.path()), &[], &[]);
        fixture.add_process(92, 1, &["other"], None, &[], &[]);
        fs::write(fixture.proc_root.join("90/cgroup"), "0::/sandbox/server\n").unwrap();
        fs::write(fixture.proc_root.join("91/cgroup"), "0::/elsewhere\n").unwrap();
        fs::write(fixture.proc_root.join("92/cgroup"), "0::/sandbox-other\n").unwrap();
        let mut args = fixture.args();
        args.cgroup = Some("/sandbox".to_owned());
        let ledger = capture(&args, &fixture.environment()).unwrap();
        let processes = ledger["processes"].as_array().unwrap();
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0]["pid"], 90);
        assert_eq!(processes[0]["membership"], "cgroup");
        assert_eq!(processes[1]["pid"], 91);
        assert_eq!(processes[1]["membership"], "descendant");
    }

    #[test]
    fn barrier_capture_is_immutable_and_refuses_symlinks() {
        let fixture = Fixture::new();
        let mut args = fixture.args();
        args.barrier = Some("checkpoint_1".to_owned());
        let ledger = capture(&args, &fixture.environment()).unwrap();
        let filename = write_ledger(&args, &ledger).unwrap();
        assert_eq!(filename, "observed-checkpoint_1.json");
        let path = fixture.workspace.join(".abra").join(&filename);
        let original = fs::read(&path).unwrap();
        assert!(write_ledger(&args, &json!({"different": true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);

        let other = Fixture::new();
        let target = other.temp.path().join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, other.workspace.join(".abra")).unwrap();
        assert!(write_ledger(&other.args(), &json!({})).is_err());
        assert!(!target.join("observed.json").exists());
    }

    #[test]
    fn runtime_probe_has_bounded_output_and_redacts_secrets() {
        let fixture = Fixture::new();
        let node = fixture.runtime.join("node");
        fs::write(&node, "#!/bin/sh\nprintf 'v99.1.0\\nignored\\n'\n").unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let mut errors = Vec::new();
        assert_eq!(
            probe_runtimes(std::slice::from_ref(&fixture.runtime), &mut errors)["node"],
            "v99.1.0"
        );
        assert!(errors.is_empty());

        fs::write(&node, "#!/bin/sh\necho sk-live-secret\n").unwrap();
        let mut errors = Vec::new();
        assert!(
            probe_runtimes(std::slice::from_ref(&fixture.runtime), &mut errors)["node"].is_null()
        );
    }

    #[test]
    fn parent_cgroup_limits_are_effective() {
        let fixture = Fixture::new();
        let root = fixture.temp.path().join("cgroup");
        let sandbox = root.join("sandbox");
        let child = sandbox.join("child");
        fs::create_dir_all(&child).unwrap();
        for (directory, memory, cpu) in [
            (&root, "max", "max 100000"),
            (&sandbox, "104857600", "50000 100000"),
            (&child, "209715200", "200000 100000"),
        ] {
            fs::write(directory.join("memory.max"), memory).unwrap();
            fs::write(directory.join("cpu.max"), cpu).unwrap();
            fs::write(directory.join("cpuset.cpus.effective"), "0-3").unwrap();
        }
        let mut args = fixture.args();
        args.cgroup = Some("/sandbox/child".to_owned());
        args.cgroup_root = root;
        let mut errors = Vec::new();
        let resources = resource_info(&args, &mut errors);
        assert_eq!(resources["effective_memory_bytes"], 104_857_600_u64);
        assert_eq!(resources["effective_cpu_millicores"], 500);
    }

    #[test]
    fn arguments_and_intervals_are_validated_before_collection() {
        let fixture = Fixture::new();
        let mut args = fixture.args();
        args.barrier = Some("../escape".to_owned());
        assert!(validate(&args).unwrap_err().to_string().contains("barrier"));
        args.barrier = None;
        args.once = false;
        args.interval = f64::NAN;
        assert!(validate(&args)
            .unwrap_err()
            .to_string()
            .contains("intervals"));
    }
}
