use abra_core::{
    cas::{materialize, Hash},
    manifest::{Fingerprint, NativeBlobRef},
    store::AbraStore,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "abra-fc",
    version,
    about = "Run Abra capsules in Firecracker microVMs"
)]
struct Cli {
    #[arg(long, env = "ABRA_ROOT", global = true)]
    root: Option<PathBuf>,
    #[arg(
        long,
        env = "ABRA_FC_BINARY",
        default_value = "firecracker",
        global = true
    )]
    firecracker: PathBuf,
    #[arg(long, env = "ABRA_FC_SSH_KEY", global = true)]
    ssh_key: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    Up {
        #[arg(long)]
        slot: u8,
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long)]
        kernel: PathBuf,
        #[arg(long, default_value_t = 512)]
        mem: u32,
        #[arg(long, default_value_t = 1)]
        vcpus: u8,
        #[arg(long)]
        token: Option<String>,
    },
    Snapshot {
        #[arg(long)]
        slot: u8,
        #[arg(long)]
        capsule: String,
        #[arg(long)]
        diff: bool,
    },
    Restore {
        #[arg(long)]
        slot: u8,
        #[arg(long)]
        capsule: String,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long, env = "ABRA_FC_KERNEL")]
        kernel: Option<PathBuf>,
        #[arg(long, env = "ABRA_FC_ROOTFS")]
        rootfs: Option<PathBuf>,
        #[arg(long, env = "ABRA_FC_MEM")]
        mem: Option<u32>,
        #[arg(long, env = "ABRA_FC_VCPUS")]
        vcpus: Option<u8>,
    },
    Down {
        #[arg(long)]
        slot: u8,
    },
    Ls,
    Fingerprint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    kernel: PathBuf,
    base_rootfs: PathBuf,
    ssh_key: PathBuf,
    mem_mib: u32,
    vcpus: u8,
}

#[derive(Clone, Debug, Default)]
struct RestoreOverrides {
    kernel: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    ssh_key: Option<PathBuf>,
    mem_mib: Option<u32>,
    vcpus: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SlotState {
    slot: u8,
    pid: u32,
    #[serde(default)]
    pid_starttime: u64,
    api_socket: PathBuf,
    tap: String,
    host_ip: String,
    guest_ip: String,
    guest_mac: String,
    rootfs: PathBuf,
    kernel: PathBuf,
    mem_mib: u32,
    vcpus: u8,
    status: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = cli.root.unwrap_or_else(default_root);
    match cli.command {
        Action::Up {
            slot,
            rootfs,
            kernel,
            mem,
            vcpus,
            token,
        } => {
            let key = resolve_key(cli.ssh_key, &rootfs)?;
            let state = up(
                &root,
                &cli.firecracker,
                slot,
                Config {
                    kernel,
                    base_rootfs: rootfs,
                    ssh_key: key,
                    mem_mib: mem,
                    vcpus,
                },
                token.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Action::Snapshot {
            slot,
            capsule,
            diff,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot(
                    &root,
                    &cli.firecracker,
                    slot,
                    &capsule,
                    diff
                )?)?
            );
        }
        Action::Restore {
            slot,
            capsule,
            snapshot,
            kernel,
            rootfs,
            mem,
            vcpus,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&restore(
                    &root,
                    &cli.firecracker,
                    RestoreOverrides {
                        kernel,
                        rootfs,
                        ssh_key: cli.ssh_key,
                        mem_mib: mem,
                        vcpus,
                    },
                    slot,
                    &capsule,
                    snapshot.as_deref()
                )?)?
            );
        }
        Action::Down { slot } => down(&root, slot)?,
        Action::Ls => list(&root)?,
        Action::Fingerprint => println!(
            "{}",
            serde_json::to_string_pretty(&fingerprint(&cli.firecracker)?)?
        ),
    }
    Ok(())
}

fn default_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| ".".into())
        .join(".abra")
}

fn adapter_root(root: &Path) -> PathBuf {
    root.join("firecracker")
}
fn slot_dir(root: &Path, slot: u8) -> PathBuf {
    adapter_root(root).join("slots").join(slot.to_string())
}
fn state_path(root: &Path, slot: u8) -> PathBuf {
    slot_dir(root, slot).join("state.json")
}

fn resolve_key(explicit: Option<PathBuf>, rootfs: &Path) -> Result<PathBuf> {
    let key = explicit
        .filter(|p| p.is_file())
        .ok_or("SSH key not found; set --ssh-key or ABRA_FC_SSH_KEY")?;
    if key.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(format!("SSH key must have mode 0600: {}", key.display()).into());
    }
    let _ = rootfs;
    Ok(key)
}

fn network(slot: u8) -> (String, String, String, String) {
    let tap = format!("osdtap{slot}");
    let host = format!("172.30.{slot}.1");
    let guest = format!("172.30.{slot}.2");
    let mac = format!("06:00:AC:1E:{slot:02X}:02");
    (tap, host, guest, mac)
}

fn up(root: &Path, fc: &Path, slot: u8, config: Config, token: Option<&str>) -> Result<SlotState> {
    require_file(&config.kernel)?;
    require_file(&config.base_rootfs)?;
    require_file(&config.ssh_key)?;
    let _ = down(root, slot);
    let dir = slot_dir(root, slot);
    create_slot_dir(root, slot)?;
    let rootfs = dir.join("rootfs.ext4");
    fs::copy(&config.base_rootfs, &rootfs)?;
    if let Some(token) = token {
        validate_token(token)?;
        inject_token(&rootfs, token)?;
    }
    create_adapter_root(root)?;
    fs::write(
        adapter_root(root).join("config.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    start_vm(root, fc, slot, config, rootfs)
}

fn start_vm(
    root: &Path,
    fc: &Path,
    slot: u8,
    config: Config,
    rootfs: PathBuf,
) -> Result<SlotState> {
    let dir = slot_dir(root, slot);
    create_slot_dir(root, slot)?;
    let socket = dir.join("firecracker.sock");
    let log = dir.join("firecracker.log");
    let stdout = fs::File::create(dir.join("stdout.log"))?;
    let stderr = fs::File::create(dir.join("stderr.log"))?;
    let (tap, host_ip, guest_ip, guest_mac) = network(slot);
    setup_network(&tap, &host_ip, &guest_ip, &guest_mac)?;
    let mut child = Command::new(fc)
        .args(["--api-sock"])
        .arg(&socket)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    if let Err(error) = wait_path(&socket, Duration::from_secs(5)) {
        cleanup_child(&mut child);
        teardown_network(&tap);
        return Err(error);
    }
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let configured = (|| -> Result<()> {
        fs::File::create(&log)?;
        api(
            &socket,
            "PUT",
            "/logger",
            &json!({"log_path":log,"level":"Info","show_level":true,"show_log_origin":true}),
        )?;
        api(
            &socket,
            "PUT",
            "/machine-config",
            &json!({"vcpu_count":config.vcpus,"mem_size_mib":config.mem_mib,"smt":false,"track_dirty_pages":true}),
        )?;
        let boot = format!("console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/usr/local/bin/os-desktop-init.sh ip={guest_ip}::{host_ip}:255.255.255.252::eth0:off");
        api(
            &socket,
            "PUT",
            "/boot-source",
            &json!({"kernel_image_path":config.kernel,"boot_args":boot}),
        )?;
        api(
            &socket,
            "PUT",
            "/drives/rootfs",
            &json!({"drive_id":"rootfs","path_on_host":rootfs,"is_root_device":true,"is_read_only":false}),
        )?;
        api(
            &socket,
            "PUT",
            "/network-interfaces/net1",
            &json!({"iface_id":"net1","guest_mac":guest_mac,"host_dev_name":tap}),
        )?;
        api(
            &socket,
            "PUT",
            "/actions",
            &json!({"action_type":"InstanceStart"}),
        )?;
        Ok(())
    })();
    if let Err(error) = configured {
        cleanup_child(&mut child);
        teardown_network(&tap);
        let _ = fs::remove_file(&socket);
        return Err(error);
    }
    let state = SlotState {
        slot,
        pid: child.id(),
        pid_starttime: proc_starttime(child.id()).unwrap_or(0),
        api_socket: socket,
        tap,
        host_ip,
        guest_ip,
        guest_mac,
        rootfs,
        kernel: config.kernel,
        mem_mib: config.mem_mib,
        vcpus: config.vcpus,
        status: "running".into(),
    };
    write_state(root, &state)?;
    if let Err(error) = wait_ssh(&state, &config.ssh_key, Duration::from_secs(90)) {
        cleanup_child(&mut child);
        teardown_network(&state.tap);
        let _ = fs::remove_file(&state.api_socket);
        return Err(error);
    }
    Ok(state)
}

fn snapshot(root: &Path, fc: &Path, slot: u8, capsule: &str, diff: bool) -> Result<Value> {
    if diff {
        return Err(
            "differential snapshots are unsupported until chained restore is implemented".into(),
        );
    }
    let state = read_state(root, slot)?;
    ensure_running(&state)?;
    let config: Config =
        serde_json::from_slice(&fs::read(adapter_root(root).join("config.json"))?)?;
    let portable = ssh_output(
        &state,
        &config.ssh_key,
        "abra --root /var/lib/abra --json snapshot /workspace; sync",
    )?;
    let portable: Value = serde_json::from_str(&portable)?;
    let portable_snapshot = portable
        .get("snapshot_id")
        .and_then(Value::as_str)
        .ok_or("guest snapshot response lacks snapshot_id")?;
    let host_status = Command::new(std::env::current_exe()?.with_file_name("abra"))
        .args([
            "--root",
            root.to_str().ok_or("non-UTF8 root")?,
            "--json",
            "status",
        ])
        .output()?;
    if !host_status.status.success() {
        return Err("could not determine host Abra peer id".into());
    }
    let host_status: Value = serde_json::from_slice(&host_status.stdout)?;
    let host_peer = host_status
        .get("peer_id")
        .and_then(Value::as_str)
        .ok_or("host status lacks peer_id")?;
    ssh(&state, &config.ssh_key,
        &format!("abra --root /var/lib/abra send '{host_peer}' --capsule '{portable_snapshot}' >/dev/null"))?;
    let portable_hash: Hash = portable_snapshot.parse()?;
    let receive_started = Instant::now();
    while receive_started.elapsed() < Duration::from_secs(30) {
        if AbraStore::open(root)?
            .capsules
            .get(&capsule.parse()?)
            .and_then(|cap| cap.snapshot(&portable_hash))
            .is_some()
        {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    if AbraStore::open(root)?
        .capsules
        .get(&capsule.parse()?)
        .and_then(|cap| cap.snapshot(&portable_hash))
        .is_none()
    {
        return Err("portable guest snapshot was not received before native capture".into());
    }
    api(
        &state.api_socket,
        "PATCH",
        "/vm",
        &json!({"state":"Paused"}),
    )?;
    let result = (|| {
        let snap_dir = slot_dir(root, slot).join("snapshots").join(epoch_id());
        fs::create_dir_all(&snap_dir)?;
        let vmstate = snap_dir.join("vmstate");
        let memory = snap_dir.join("memory");
        api(
            &state.api_socket,
            "PUT",
            "/snapshot/create",
            &json!({
                "snapshot_type": "Full",
                "snapshot_path": vmstate,
                "mem_file_path": memory
            }),
        )?;
        let fp = fingerprint_for_snapshot(fc, &vmstate)?;
        fs::write(
            adapter_root(root).join("fingerprint.json"),
            serde_json::to_vec_pretty(&fp)?,
        )?;
        let response = control(
            root,
            &json!({"op":"native-attach","capsule":capsule,"fingerprint":fp,
            "parent_snapshot":portable_snapshot,"snapshot_type":"Full","artifact_root":slot_dir(root, slot),
            "artifacts":[{"role":"vmstate","path":vmstate},{"role":"memory","path":memory},{"role":"disk","path":state.rootfs}]}),
        )?;
        snapshot_output(portable_snapshot, &response)
    })();
    let resumed = api(
        &state.api_socket,
        "PATCH",
        "/vm",
        &json!({"state":"Resumed"}),
    );
    if let Err(error) = resumed {
        eprintln!("warning: failed to resume slot {slot}: {error}");
    }
    result
}

fn restore(
    root: &Path,
    fc: &Path,
    overrides: RestoreOverrides,
    slot: u8,
    capsule: &str,
    requested: Option<&str>,
) -> Result<Value> {
    let started = Instant::now();
    let store = AbraStore::open(root)?;
    let capsule_id: Hash = capsule.parse()?;
    let cap = store.capsules.get(&capsule_id).ok_or("unknown capsule")?;
    let snapshot_id = match requested {
        Some(id) => id.parse()?,
        None => {
            cap.label("main")
                .ok_or("capsule has no main head")?
                .snapshot_id
        }
    };
    let record = cap
        .snapshot(&snapshot_id)
        .ok_or("snapshot not found in capsule")?;
    let config = resolve_restore_config(root, overrides)?;
    let local = local_fingerprint(root, fc)?;
    let matched = matching_native(record.raw.manifest().native.as_deref(), &local);
    if let Some((vmstate, memory, disk)) = matched {
        let native_attempt = (|| -> Result<Value> {
            let _ = down(root, slot);
            let dir = slot_dir(root, slot);
            create_slot_dir(root, slot)?;
            let vmstate_path = dir.join("restore.vmstate");
            let memory_path = dir.join("restore.memory");
            let disk_path = dir.join("rootfs.ext4");
            store.cas.copy_to_file(&vmstate.blob, &vmstate_path)?;
            store.cas.copy_to_file(&memory.blob, &memory_path)?;
            store.cas.copy_to_file(&disk.blob, &disk_path)?;
            let (tap, host_ip, guest_ip, guest_mac) = network(slot);
            setup_network(&tap, &host_ip, &guest_ip, &guest_mac)?;
            let socket = dir.join("firecracker.sock");
            let mut child = Command::new(fc)
                .args(["--api-sock"])
                .arg(&socket)
                .stdout(Stdio::from(fs::File::create(dir.join("stdout.log"))?))
                .stderr(Stdio::from(fs::File::create(dir.join("stderr.log"))?))
                .spawn()?;
            if let Err(error) = wait_path(&socket, Duration::from_secs(5)) {
                cleanup_child(&mut child);
                teardown_network(&tap);
                return Err(error);
            }
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
            let configured = (|| -> Result<()> {
                api(
                    &socket,
                    "PUT",
                    "/snapshot/load",
                    &json!({"snapshot_path":vmstate_path,"mem_file_path":memory_path,
            "track_dirty_pages":true,"resume_vm":false,"network_overrides":[{"iface_id":"net1","host_dev_name":tap,"guest_mac":guest_mac}]}),
                )?;
                api(
                    &socket,
                    "PATCH",
                    "/drives/rootfs",
                    &json!({"drive_id":"rootfs","path_on_host":disk_path}),
                )?;
                api(&socket, "PATCH", "/vm", &json!({"state":"Resumed"}))?;
                Ok(())
            })();
            if let Err(error) = configured {
                cleanup_child(&mut child);
                teardown_network(&tap);
                let _ = fs::remove_file(&socket);
                return Err(error);
            }
            let state = SlotState {
                slot,
                pid: child.id(),
                pid_starttime: proc_starttime(child.id()).unwrap_or(0),
                api_socket: socket,
                tap,
                host_ip,
                guest_ip,
                guest_mac,
                rootfs: disk_path,
                kernel: config.kernel.clone(),
                mem_mib: config.mem_mib,
                vcpus: config.vcpus,
                status: "running".into(),
            };
            write_state(root, &state)?;
            if let Err(error) = wait_ssh(&state, &config.ssh_key, Duration::from_secs(30)) {
                cleanup_child(&mut child);
                teardown_network(&state.tap);
                return Err(error);
            }
            Ok(
                json!({"mode":"native","snapshot_id":snapshot_id,"fingerprint":local,"restore_ms":started.elapsed().as_millis()}),
            )
        })();
        match native_attempt {
            Ok(result) => return Ok(result),
            Err(error) => {
                eprintln!("native restore unavailable; using portable fallback: {error}");
                let _ = down(root, slot);
            }
        }
    }
    let state = up(root, fc, slot, config.clone(), None)?;
    let temp = tempfile::tempdir()?;
    materialize(
        &store.cas,
        &record.raw.manifest().files.ok_or("snapshot lacks files")?,
        temp.path(),
    )?;
    rsync_guest(temp.path(), &state, &config.ssh_key, "/workspace/")?;
    let recipes = record.raw.manifest().recipes.clone().unwrap_or_default();
    eprintln!(
        "recipes (data only; not executed): {}",
        serde_json::to_string_pretty(&recipes)?
    );
    Ok(
        json!({"mode":"portable-fallback","snapshot_id":snapshot_id,"fingerprint":local,"restore_ms":started.elapsed().as_millis(),"recipes":recipes}),
    )
}

fn matching_native<'a>(
    native: Option<&'a [NativeBlobRef]>,
    fp: &Fingerprint,
) -> Option<(&'a NativeBlobRef, &'a NativeBlobRef, &'a NativeBlobRef)> {
    let matching: Vec<_> = native?.iter().filter(|n| &n.fingerprint == fp).collect();
    Some((
        matching.iter().find(|n| n.role == "vmstate")?,
        matching.iter().find(|n| n.role == "memory")?,
        matching.iter().find(|n| n.role == "disk")?,
    ))
}

fn snapshot_output(portable_snapshot: &str, native_response: &Value) -> Result<Value> {
    let native_snapshot = native_response
        .get("snapshot_id")
        .and_then(Value::as_str)
        .ok_or("native-attach response lacks snapshot_id")?;
    Ok(json!({
        "portable_snapshot_id": portable_snapshot,
        "native_snapshot_id": native_snapshot,
    }))
}

fn resolve_restore_config(root: &Path, overrides: RestoreOverrides) -> Result<Config> {
    let path = adapter_root(root).join("config.json");
    let existing = match fs::read(&path) {
        Ok(bytes) => Some(serde_json::from_slice::<Config>(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let config_was_absent = existing.is_none();
    let missing = if config_was_absent {
        let mut names = Vec::new();
        if overrides.kernel.is_none() {
            names.push("--kernel or ABRA_FC_KERNEL");
        }
        if overrides.rootfs.is_none() {
            names.push("--rootfs or ABRA_FC_ROOTFS");
        }
        if overrides.ssh_key.is_none() {
            names.push("--ssh-key or ABRA_FC_SSH_KEY");
        }
        names
    } else {
        Vec::new()
    };
    if !missing.is_empty() {
        return Err(format!(
            "restore config is absent at {}; missing: {}",
            path.display(),
            missing.join(", ")
        )
        .into());
    }
    let mut config = match existing {
        Some(config) => config,
        None => Config {
            kernel: overrides.kernel.clone().unwrap(),
            base_rootfs: overrides.rootfs.clone().unwrap(),
            ssh_key: overrides.ssh_key.clone().unwrap(),
            mem_mib: overrides.mem_mib.unwrap_or(512),
            vcpus: overrides.vcpus.unwrap_or(1),
        },
    };
    if let Some(value) = overrides.kernel {
        config.kernel = value;
    }
    if let Some(value) = overrides.rootfs {
        config.base_rootfs = value;
    }
    if let Some(value) = overrides.ssh_key {
        config.ssh_key = value;
    }
    if let Some(value) = overrides.mem_mib {
        config.mem_mib = value;
    }
    if let Some(value) = overrides.vcpus {
        config.vcpus = value;
    }
    require_file(&config.kernel)?;
    require_file(&config.base_rootfs)?;
    resolve_key(Some(config.ssh_key.clone()), &config.base_rootfs)?;
    if config_was_absent {
        create_adapter_root(root)?;
        fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    }
    Ok(config)
}

fn fingerprint(fc: &Path) -> Result<Fingerprint> {
    if let Ok(fake) = std::env::var("ABRA_FC_FAKE_FINGERPRINT") {
        return Ok(serde_json::from_str(&fake)?);
    }
    let output = Command::new(fc).arg("--version").output()?;
    let version = String::from_utf8(output.stdout)?
        .split_whitespace()
        .find(|x| x.starts_with('v'))
        .ok_or("unrecognized Firecracker version")?
        .trim_start_matches('v')
        .to_owned();
    let major = if let Ok(value) = std::env::var("ABRA_FC_SNAPSHOT_FORMAT_MAJOR") {
        value.parse()?
    } else {
        let output = Command::new(fc).arg("--snapshot-version").output()?;
        if !output.status.success() {
            return Err("Firecracker --snapshot-version failed".into());
        }
        let text = String::from_utf8(output.stdout)?;
        text.trim()
            .trim_start_matches('v')
            .split('.')
            .next()
            .ok_or("unrecognized Firecracker snapshot version")?
            .parse()?
    };
    let _ = version;
    Ok(Fingerprint {
        os: "linux".into(),
        arch: std::env::consts::ARCH.into(),
        hypervisor: "firecracker".into(),
        snapshot_format_major: major,
        cpu_template: std::env::var("ABRA_FC_CPU_TEMPLATE").unwrap_or_else(|_| "-".into()),
        cpu_identity: live_cpu_identity()?,
    })
}

fn local_fingerprint(_root: &Path, fc: &Path) -> Result<Fingerprint> {
    // Always probe the live receiver. fingerprint.json describes a capture and
    // must never be trusted as receiver identity.
    fingerprint(fc)
}

fn fingerprint_for_snapshot(fc: &Path, vmstate: &Path) -> Result<Fingerprint> {
    let mut fp = fingerprint(fc)?;
    let output = Command::new(fc)
        .arg("--describe-snapshot")
        .arg(vmstate)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let description = format!("{}\n{}", stdout, String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("Firecracker could not describe snapshot: {description}").into());
    }
    // Firecracker 1.16 prints only `v<snapshot-data-version>` on stdout.
    // Parse that dedicated command output, never stderr/release banner text.
    let data_version = stdout.trim();
    let version = data_version
        .split(|character: char| character.is_whitespace() || character == '"' || character == ':')
        .map(|word| word.trim_start_matches('v').trim_matches(','))
        .find(|word| {
            let parts: Vec<_> = word.split('.').collect();
            parts.len() == 3 && parts.iter().all(|part| part.parse::<u64>().is_ok())
        })
        .ok_or_else(|| format!("could not parse snapshot data version from: {description}"))?;
    fp.snapshot_format_major = version.split('.').next().unwrap().parse()?;
    Ok(fp)
}

fn live_cpu_identity() -> Result<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
    let field = |name: &str| {
        cpuinfo
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name).then(|| value.trim().to_owned())
            })
            .unwrap_or_else(|| "unknown".into())
    };
    Ok(format!(
        "vendor={};family={};model={};stepping={}",
        field("vendor_id"),
        field("cpu family"),
        field("model"),
        field("stepping")
    ))
}

fn api(socket: &Path, method: &str, endpoint: &str, body: &Value) -> Result<()> {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--config",
            "/dev/null",
            "--write-out",
            "\n%{http_code}",
            "--unix-socket",
        ])
        .arg(socket)
        .args([
            "-X",
            method,
            "-H",
            "Content-Type: application/json",
            "--data",
        ])
        .arg(serde_json::to_string(body)?)
        .arg(format!("http://localhost{endpoint}"))
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let (response, status) = text.rsplit_once('\n').unwrap_or((&text, "000"));
    if !output.status.success() || !status.starts_with('2') {
        return Err(
            format!("Firecracker {method} {endpoint} failed HTTP {status}: {response}").into(),
        );
    }
    Ok(())
}

fn setup_network(tap: &str, host: &str, guest: &str, mac: &str) -> Result<()> {
    if !Command::new("ip")
        .args(["link", "show", "dev", tap])
        .status()?
        .success()
    {
        run("sudo", &["ip", "tuntap", "add", "dev", tap, "mode", "tap"])?;
    }
    let _ = Command::new("sudo")
        .args(["ip", "addr", "flush", "dev", tap, "scope", "global"])
        .status();
    run(
        "sudo",
        &["ip", "addr", "add", &format!("{host}/30"), "dev", tap],
    )?;
    run("sudo", &["ip", "link", "set", "dev", tap, "up"])?;
    run(
        "sudo",
        &[
            "ip",
            "neigh",
            "replace",
            guest,
            "lladdr",
            mac,
            "dev",
            tap,
            "nud",
            "permanent",
        ],
    )?;
    run("sudo", &["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
    if !Command::new("sudo")
        .args([
            "iptables",
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            "172.30.0.0/16",
            "-j",
            "MASQUERADE",
        ])
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        run(
            "sudo",
            &[
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "172.30.0.0/16",
                "-j",
                "MASQUERADE",
            ],
        )?;
    }
    Ok(())
}

fn down(root: &Path, slot: u8) -> Result<()> {
    if let Ok(mut state) = read_state(root, slot) {
        if state.pid != 0 && process_matches(&state) {
            let _ = Command::new("kill").arg(state.pid.to_string()).status();
            for _ in 0..20 {
                if !pid_alive(state.pid) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if pid_alive(state.pid) {
                let _ = Command::new("kill")
                    .args(["-9", &state.pid.to_string()])
                    .status();
            }
        }
        let _ = Command::new("sudo")
            .args(["ip", "link", "del", &state.tap])
            .status();
        let _ = fs::remove_file(&state.api_socket);
        state.status = "stopped".into();
        state.pid = 0;
        write_state(root, &state)?;
    }
    cleanup_global_network_if_idle(root);
    Ok(())
}

fn list(root: &Path) -> Result<()> {
    let dir = adapter_root(root).join("slots");
    let mut states = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path().join("state.json")) {
                if let Ok(mut state) = serde_json::from_slice::<SlotState>(&bytes) {
                    if state.pid != 0 && !pid_alive(state.pid) {
                        state.status = "stale".into();
                    }
                    states.push(state);
                }
            }
        }
    }
    states.sort_by_key(|s| s.slot);
    println!("{}", serde_json::to_string_pretty(&states)?);
    Ok(())
}

fn ssh(state: &SlotState, key: &Path, command: &str) -> Result<()> {
    let status = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=2",
            "-i",
        ])
        .arg(key)
        .arg(format!("root@{}", state.guest_ip))
        .arg(command)
        .status()?;
    if !status.success() {
        return Err(format!("guest SSH command failed with {status}").into());
    }
    Ok(())
}

fn ssh_output(state: &SlotState, key: &Path, command: &str) -> Result<String> {
    let output = Command::new("ssh")
        .args([
            "-q",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=2",
            "-i",
        ])
        .arg(key)
        .arg(format!("root@{}", state.guest_ip))
        .arg(command)
        .output()?;
    if !output.status.success() {
        return Err(format!("guest SSH command failed with {}", output.status).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn wait_ssh(state: &SlotState, key: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if ssh(state, key, "true").is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "guest SSH at {} was not ready after {}s",
        state.guest_ip,
        timeout.as_secs()
    )
    .into())
}

fn rsync_guest(source: &Path, state: &SlotState, key: &Path, destination: &str) -> Result<()> {
    ssh(state, key, &format!("mkdir -p {destination}"))?;
    let status = Command::new("scp")
        .args([
            "-q",
            "-r",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-i",
        ])
        .arg(key)
        .arg(format!("{}/.", source.display()))
        .arg(format!("root@{}:{destination}", state.guest_ip))
        .status()?;
    if !status.success() {
        return Err("scp to guest failed".into());
    }
    Ok(())
}

fn control(root: &Path, request: &Value) -> Result<Value> {
    let mut stream = UnixStream::connect(root.join("cadabra.sock"))?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let response: Value = serde_json::from_str(&line)?;
    if response.get("ok") == Some(&Value::Bool(true)) {
        return Ok(response["result"].clone());
    }
    Err(response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("cadabra control error")
        .to_owned()
        .into())
}

fn write_state(root: &Path, state: &SlotState) -> Result<()> {
    create_slot_dir(root, state.slot)?;
    fs::write(
        state_path(root, state.slot),
        serde_json::to_vec_pretty(state)?,
    )?;
    Ok(())
}
fn read_state(root: &Path, slot: u8) -> Result<SlotState> {
    Ok(serde_json::from_slice(&fs::read(state_path(root, slot))?)?)
}
fn ensure_running(state: &SlotState) -> Result<()> {
    if state.pid != 0 && pid_alive(state.pid) {
        Ok(())
    } else {
        Err("slot is not running".into())
    }
}
fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success())
}
fn proc_starttime(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()?
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
fn process_matches(state: &SlotState) -> bool {
    let comm = fs::read_to_string(format!("/proc/{}/comm", state.pid)).unwrap_or_default();
    (comm.trim() == "firecracker" || comm.trim() == "jailer")
        && state.pid_starttime != 0
        && proc_starttime(state.pid) == Some(state.pid_starttime)
}
fn cleanup_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
fn teardown_network(tap: &str) {
    let _ = Command::new("sudo")
        .args(["ip", "link", "del", tap])
        .status();
}
fn cleanup_global_network_if_idle(root: &Path) {
    let any_running = fs::read_dir(adapter_root(root).join("slots"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| fs::read(e.path().join("state.json")).ok())
        .filter_map(|b| serde_json::from_slice::<SlotState>(&b).ok())
        .any(|s| s.pid != 0 && process_matches(&s));
    if !any_running {
        let _ = Command::new("sudo")
            .args([
                "iptables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "172.30.0.0/16",
                "-j",
                "MASQUERADE",
            ])
            .status();
    }
}
fn validate_token(token: &str) -> Result<()> {
    let suffix = token
        .strip_prefix("abra-enroll/1/")
        .ok_or("invalid enrollment token format")?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid enrollment token format".into());
    }
    Ok(())
}
fn inject_token(rootfs: &Path, token: &str) -> Result<()> {
    let token_file = write_token_temp(token)?;
    let mount = tempfile::tempdir()?;
    run(
        "sudo",
        &[
            "mount",
            "-o",
            "loop,nodev,nosuid",
            rootfs.to_str().ok_or("non-UTF8 rootfs path")?,
            mount.path().to_str().ok_or("non-UTF8 mount path")?,
        ],
    )?;
    let result = (|| -> Result<()> {
        for component in [mount.path().join("etc"), mount.path().join("etc/abra")] {
            if let Ok(meta) = fs::symlink_metadata(&component) {
                if meta.file_type().is_symlink() {
                    return Err(
                        format!("refusing symlinked guest path: {}", component.display()).into(),
                    );
                }
            }
        }
        let etc = mount.path().join("etc/abra");
        run_owned(
            "sudo",
            ["mkdir", "-p", "--"]
                .into_iter()
                .map(Into::into)
                .chain([etc.as_os_str().to_owned()]),
        )?;
        let path = etc.join("token");
        guard_token_destination(&path)?;
        run_owned("sudo", token_install_args(token_file.path(), &path))?;
        let output = Command::new("sudo")
            .args(["stat", "-c", "%F:%u:%g:%a", "--"])
            .arg(&path)
            .output()?;
        if !output.status.success() {
            return Err(format!("sudo stat failed for {}", path.display()).into());
        }
        if String::from_utf8(output.stdout)?.trim() != "regular file:0:0:600" {
            return Err(format!(
                "guest token must be a root:root 0600 regular file: {}",
                path.display()
            )
            .into());
        }
        Ok(())
    })();
    let unmounted = Command::new("sudo")
        .args(["umount", mount.path().to_str().unwrap()])
        .status()?
        .success();
    if !unmounted {
        let _ = Command::new("sudo")
            .args(["umount", "-l", mount.path().to_str().unwrap()])
            .status();
    }
    token_file.close()?;
    result
}

fn guard_token_destination(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(format!(
            "guest token path must be a regular file or absent: {}",
            path.display()
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            guard_token_destination_with_sudo(path)
        }
        Err(error) => Err(error.into()),
    }
}

fn guard_token_destination_with_sudo(path: &Path) -> Result<()> {
    let output = Command::new("sudo")
        .args(["stat", "-c", "%F", "--"])
        .arg(path)
        .output()?;
    if output.status.success() {
        if String::from_utf8(output.stdout)?.trim() == "regular file" {
            return Ok(());
        }
        return Err(format!(
            "guest token path must be a regular file or absent: {}",
            path.display()
        )
        .into());
    }

    let exists = Command::new("sudo")
        .args(["test", "-e"])
        .arg(path)
        .status()?;
    if exists.success() {
        Err(format!("sudo stat failed for {}", path.display()).into())
    } else {
        Ok(())
    }
}

fn write_token_temp(token: &str) -> Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(token.as_bytes())?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn token_install_args(source: &Path, destination: &Path) -> Vec<std::ffi::OsString> {
    ["install", "-m", "0600", "-o", "root", "-g", "root", "--"]
        .into_iter()
        .map(Into::into)
        .chain([
            source.as_os_str().to_owned(),
            destination.as_os_str().to_owned(),
        ])
        .collect()
}

fn create_adapter_root(root: &Path) -> Result<()> {
    let dir = adapter_root(root);
    fs::create_dir_all(&dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn create_slot_dir(root: &Path, slot: u8) -> Result<()> {
    create_adapter_root(root)?;
    let slots = adapter_root(root).join("slots");
    fs::create_dir_all(&slots)?;
    fs::set_permissions(&slots, fs::Permissions::from_mode(0o700))?;
    let dir = slot_dir(root, slot);
    fs::create_dir_all(&dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn wait_path(path: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for {}", path.display()).into())
}
fn require_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing file: {}", path.display()).into())
    }
}
fn epoch_id() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}
fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {:?} failed: {status}", args).into())
    }
}

fn run_owned(program: &str, args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<()> {
    let args: Vec<_> = args.into_iter().collect();
    let status = Command::new(program)
        .args(&args)
        .stdout(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {args:?} failed: {status}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn token_install_uses_root_ownership_and_private_mode() {
        let args = token_install_args(Path::new("/tmp/source"), Path::new("/mnt/etc/abra/token"));
        assert_eq!(
            args,
            [
                "install",
                "-m",
                "0600",
                "-o",
                "root",
                "-g",
                "root",
                "--",
                "/tmp/source",
                "/mnt/etc/abra/token",
            ]
            .map(std::ffi::OsString::from)
        );
    }

    #[test]
    fn token_temp_file_is_private() {
        let file = write_token_temp("abra-enroll/1/test").unwrap();
        assert_eq!(
            file.as_file().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(file.path()).unwrap(),
            "abra-enroll/1/test"
        );
    }

    #[test]
    fn token_destination_guard_accepts_only_regular_file_or_absent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        guard_token_destination(&path).unwrap();

        fs::write(&path, b"old token").unwrap();
        guard_token_destination(&path).unwrap();

        fs::remove_file(&path).unwrap();
        symlink("/etc/shadow", &path).unwrap();
        assert!(guard_token_destination(&path).is_err());

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(guard_token_destination(&path).is_err());
    }

    #[test]
    fn adapter_and_slot_directories_are_private() {
        let root = tempfile::tempdir().unwrap();
        create_slot_dir(root.path(), 0).unwrap();
        for path in [
            adapter_root(root.path()),
            adapter_root(root.path()).join("slots"),
            slot_dir(root.path(), 0),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn fresh_restore_config_lists_every_missing_required_input() {
        let root = tempfile::tempdir().unwrap();
        let error = resolve_restore_config(root.path(), RestoreOverrides::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("--kernel or ABRA_FC_KERNEL"));
        assert!(error.contains("--rootfs or ABRA_FC_ROOTFS"));
        assert!(error.contains("--ssh-key or ABRA_FC_SSH_KEY"));
    }

    #[test]
    fn fresh_restore_config_is_written_and_defaults_resources() {
        let root = tempfile::tempdir().unwrap();
        let kernel = fixture_file(root.path(), "vmlinux", 0o644);
        let rootfs = fixture_file(root.path(), "rootfs.ext4", 0o644);
        let key = fixture_file(root.path(), "id_rsa", 0o600);
        let config = resolve_restore_config(
            root.path(),
            RestoreOverrides {
                kernel: Some(kernel.clone()),
                rootfs: Some(rootfs.clone()),
                ssh_key: Some(key.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(config.mem_mib, 512);
        assert_eq!(config.vcpus, 1);
        let saved: Config = serde_json::from_slice(
            &fs::read(adapter_root(root.path()).join("config.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved.kernel, kernel);
        assert_eq!(saved.base_rootfs, rootfs);
        assert_eq!(saved.ssh_key, key);
    }

    #[test]
    fn existing_restore_config_keeps_values_without_overrides() {
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            kernel: fixture_file(root.path(), "kernel", 0o644),
            base_rootfs: fixture_file(root.path(), "disk", 0o644),
            ssh_key: fixture_file(root.path(), "key", 0o600),
            mem_mib: 768,
            vcpus: 2,
        };
        fs::create_dir_all(adapter_root(root.path())).unwrap();
        fs::write(
            adapter_root(root.path()).join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        let resolved = resolve_restore_config(root.path(), RestoreOverrides::default()).unwrap();
        assert_eq!(resolved.mem_mib, 768);
        assert_eq!(resolved.vcpus, 2);
    }

    #[test]
    fn snapshot_output_names_portable_and_native_ids() {
        let output = snapshot_output("portable", &json!({"snapshot_id":"native"})).unwrap();
        assert_eq!(
            output,
            json!({
                "portable_snapshot_id":"portable",
                "native_snapshot_id":"native"
            })
        );
    }

    #[test]
    fn restore_flags_parse_into_overrides() {
        let cli = Cli::try_parse_from([
            "abra-fc",
            "--firecracker",
            "/bin/firecracker",
            "--ssh-key",
            "/tmp/key",
            "restore",
            "--slot",
            "3",
            "--capsule",
            "capsule",
            "--kernel",
            "/tmp/kernel",
            "--rootfs",
            "/tmp/rootfs",
            "--mem",
            "1024",
            "--vcpus",
            "2",
        ])
        .unwrap();
        assert_eq!(cli.firecracker, PathBuf::from("/bin/firecracker"));
        assert_eq!(cli.ssh_key, Some(PathBuf::from("/tmp/key")));
        match cli.command {
            Action::Restore {
                slot,
                kernel,
                rootfs,
                mem,
                vcpus,
                ..
            } => {
                assert_eq!(slot, 3);
                assert_eq!(kernel, Some(PathBuf::from("/tmp/kernel")));
                assert_eq!(rootfs, Some(PathBuf::from("/tmp/rootfs")));
                assert_eq!(mem, Some(1024));
                assert_eq!(vcpus, Some(2));
            }
            _ => panic!("expected restore command"),
        }
    }
}
