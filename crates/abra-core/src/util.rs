//! Small shared helpers: hex, time, durable writes.

use crate::error::{Error, Result};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::{fs, io::Write, path::Path};

/// Writes `bytes` to `path` so readers only ever see the old or the new file:
/// a fresh temporary file in the same directory, fsynced, renamed into place,
/// then the parent directory fsynced so the rename itself survives a crash.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::invalid("path has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    let tmp = parent.join(format!(".tmp-{}", rand::random::<u64>()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| Error::io(&tmp, e))?;
    file.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
    file.sync_all().map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))?;
    sync_directory(parent)
}

/// Flush a rename into the directory itself.
///
/// Unix needs this for the rename to survive a crash. Windows cannot open a
/// directory as a file and orders metadata itself, so there it does nothing.
pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| Error::io(path, e))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Take `path` out of reach of every other account on the machine.
///
/// Unix sets `0o700` on directories and `0o600` on files. Windows has no mode
/// bits, so inheritance is broken and a single full-control entry for the
/// current user is granted instead.
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = fs::symlink_metadata(path)
            .map_err(|e| Error::io(path, e))?
            .is_dir();
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(path, e))?;
    }
    #[cfg(windows)]
    windows_restrict_to_owner(path)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

#[cfg(windows)]
fn windows_restrict_to_owner(path: &Path) -> Result<()> {
    let Some(user) = std::env::var_os("USERNAME").filter(|name| !name.is_empty()) else {
        // Without an account name there is nobody to grant access to; leaving
        // inherited permissions is better than locking the store out.
        return Ok(());
    };
    // Inheritance flags belong on a container; on a file they would mark the
    // entry inherit-only, leaving the owner with no access at all.
    let directory = fs::symlink_metadata(path)
        .map_err(|e| Error::io(path, e))?
        .is_dir();
    let scope = if directory { "(OI)(CI)F" } else { "F" };
    let grant = format!("{}:{scope}", user.to_string_lossy());
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| Error::io(path, e))?;
    if !output.status.success() {
        return Err(Error::invalid(format!(
            "could not restrict {} to {}: {}",
            path.display(),
            grant,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub(crate) fn hex_decode_fixed<const N: usize>(s: &str, kind: &'static str) -> Result<[u8; N]> {
    if s.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::encoding(kind, "expected lowercase hex"));
    }
    let raw = hex::decode(s).map_err(|e| Error::encoding(kind, format!("not hex: {e}")))?;
    if raw.len() != N {
        return Err(Error::encoding(
            kind,
            format!(
                "expected {N} bytes ({} hex chars), got {}",
                N * 2,
                raw.len()
            ),
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Milliseconds since the Unix epoch.
///
/// Saturates at 0 for clocks set before 1970 rather than panicking; Abra never
/// depends on timestamps for correctness, only for ordering and display.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Implements `Display`, `FromStr`, `Serialize` and `Deserialize` as lowercase
/// hex for a newtype wrapping a fixed-size byte array.
macro_rules! hex_newtype {
    ($name:ident, $len:expr, $kind:expr) => {
        impl $name {
            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Consume into raw bytes.
            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }

            /// Wrap raw bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Lowercase hex.
            pub fn to_hex(&self) -> String {
                $crate::util::hex_encode(&self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::error::Error;
            fn from_str(s: &str) -> ::std::result::Result<Self, $crate::error::Error> {
                Ok(Self($crate::util::hex_decode_fixed::<$len>(s, $kind)?))
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                d: D,
            ) -> ::std::result::Result<Self, D::Error> {
                let s = <::std::string::String as serde::Deserialize>::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use hex_newtype;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 2, 250, 255];
        let s = hex_encode(&bytes);
        assert_eq!(s, "000102faff");
        assert_eq!(hex_decode_fixed::<5>(&s, "test").unwrap(), bytes);
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode_fixed::<4>("00112233445566", "test").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode_fixed::<2>("zzzz", "test").is_err());
    }

    #[test]
    fn now_ms_is_after_2020() {
        assert!(now_ms() > 1_577_836_800_000);
    }

    #[test]
    fn owner_only_paths_stay_writable_by_this_process() {
        let directory = tempfile::tempdir().unwrap();
        restrict_to_owner(directory.path()).unwrap();
        let file = directory.path().join("secret");
        atomic_write(&file, b"one").unwrap();
        restrict_to_owner(&file).unwrap();
        // Hardening must not lock the owner out of its own store.
        atomic_write(&file, b"two").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"two");
        sync_directory(directory.path()).unwrap();
    }
}
