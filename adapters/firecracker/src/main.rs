//! `abra-fc` drives Firecracker microVMs, which exist on Linux only. The whole
//! implementation is compiled behind `cfg(unix)` so `cargo check --workspace`
//! still covers this crate on Windows.

#[cfg(unix)]
#[path = "fc.rs"]
mod fc;

#[cfg(unix)]
fn main() -> fc::Result<()> {
    fc::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("abra-fc requires Linux");
    std::process::exit(2);
}
