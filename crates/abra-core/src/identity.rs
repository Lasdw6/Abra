//! Device identity and persistent device secrets (SPEC §0, §7.1).
use crate::util::hex_newtype;
use crate::{Error, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);
hex_newtype!(PeerId, 32, "peer id");
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortId([u8; 4]);
hex_newtype!(ShortId, 4, "short id");
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);
hex_newtype!(Signature, 64, "signature");

impl PeerId {
    pub fn short(&self) -> ShortId {
        let h = blake3::hash(&self.0);
        let mut b = [0; 4];
        b.copy_from_slice(&h.as_bytes()[..4]);
        ShortId(b)
    }
    pub fn verify(&self, domain: &str, payload: &[u8], sig: &Signature) -> Result<()> {
        let k =
            VerifyingKey::from_bytes(&self.0).map_err(|e| Error::BadSignature(e.to_string()))?;
        k.verify_strict(
            &signature_preimage(domain, payload),
            &ed25519_dalek::Signature::from_bytes(&sig.0),
        )
        .map_err(|e| Error::BadSignature(e.to_string()))
    }
    pub fn is_valid_key(&self) -> bool {
        VerifyingKey::from_bytes(&self.0).is_ok()
    }
}
/// `abra-sig-v1 || NUL || domain || NUL || payload` (SPEC §0).
pub fn signature_preimage(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = b"abra-sig-v1\0".to_vec();
    v.extend_from_slice(domain.as_bytes());
    v.push(0);
    v.extend_from_slice(payload);
    v
}
/// Load a key file, or create and save a fresh one when it does not exist.
fn load_or_generate_with<T>(
    path: &Path,
    load: impl FnOnce(&Path) -> Result<T>,
    generate: impl FnOnce() -> T,
    save: impl FnOnce(&T, &Path) -> Result<()>,
) -> Result<T> {
    match load(path) {
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            let fresh = generate();
            save(&fresh, path)?;
            Ok(fresh)
        }
        loaded => loaded,
    }
}

#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.short_id())
    }
}
impl Identity {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_secret_bytes(b: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(b),
        }
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.signing.verifying_key().to_bytes())
    }
    pub fn short_id(&self) -> ShortId {
        self.peer_id().short()
    }
    pub fn sign(&self, d: &str, p: &[u8]) -> Signature {
        Signature(self.signing.sign(&signature_preimage(d, p)).to_bytes())
    }
    pub fn save(&self, p: impl AsRef<Path>) -> Result<()> {
        save_private(p.as_ref(), &self.secret_bytes())
    }
    pub fn load(p: impl AsRef<Path>) -> Result<Self> {
        let p = p.as_ref();
        let b = fs::read(p).map_err(|e| Error::io(p, e))?;
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| Error::corrupt("identity key", "expected 32 bytes"))?;
        Ok(Self::from_secret_bytes(&a))
    }
    pub fn load_or_generate(p: impl AsRef<Path>) -> Result<Self> {
        load_or_generate_with(
            p.as_ref(),
            |p| Self::load(p),
            Self::generate,
            |x, p| x.save(p),
        )
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceFile {
    spec: String,
    ed25519_secret: String,
    x25519_secret: String,
    relay_discovery_key: String,
}
/// The three independently generated persistent device secrets (SPEC §0, §7.1).
#[derive(Clone)]
pub struct DeviceKeys {
    pub identity: Identity,
    pub x25519_secret: [u8; 32],
    pub relay_discovery_key: [u8; 32],
}
impl DeviceKeys {
    pub fn generate() -> Self {
        let mut x = [0; 32];
        let mut r = [0; 32];
        OsRng.fill_bytes(&mut x);
        OsRng.fill_bytes(&mut r);
        Self {
            identity: Identity::generate(),
            x25519_secret: x,
            relay_discovery_key: r,
        }
    }
    pub fn x25519_public(&self) -> [u8; 32] {
        XPublicKey::from(&StaticSecret::from(self.x25519_secret)).to_bytes()
    }
    pub fn save(&self, p: impl AsRef<Path>) -> Result<()> {
        let d = DeviceFile {
            spec: crate::SPEC.into(),
            ed25519_secret: hex::encode(self.identity.secret_bytes()),
            x25519_secret: hex::encode(self.x25519_secret),
            relay_discovery_key: hex::encode(self.relay_discovery_key),
        };
        save_private(p.as_ref(), &crate::canonical::to_vec(&d)?)
    }
    pub fn load(p: impl AsRef<Path>) -> Result<Self> {
        let p = p.as_ref();
        let d: DeviceFile = serde_json::from_slice(&fs::read(p).map_err(|e| Error::io(p, e))?)?;
        if d.spec != crate::SPEC {
            return Err(Error::UnsupportedSpec {
                found: d.spec,
                expected: crate::SPEC.into(),
            });
        }
        Ok(Self {
            identity: Identity::from_secret_bytes(&d.ed25519_secret.parse_hex()?),
            x25519_secret: d.x25519_secret.parse_hex()?,
            relay_discovery_key: d.relay_discovery_key.parse_hex()?,
        })
    }
    pub fn load_or_generate(p: impl AsRef<Path>) -> Result<Self> {
        load_or_generate_with(
            p.as_ref(),
            |p| Self::load(p),
            Self::generate,
            |x, p| x.save(p),
        )
    }
}
trait ParseHex {
    fn parse_hex<const N: usize>(&self) -> Result<[u8; N]>;
}
impl ParseHex for String {
    fn parse_hex<const N: usize>(&self) -> Result<[u8; N]> {
        crate::util::hex_decode_fixed(self, "key")
    }
}
fn save_private(p: &Path, b: &[u8]) -> Result<()> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(|e| Error::io(d, e))?
    }
    #[cfg(unix)]
    {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p)
            .map_err(|e| Error::io(p, e))?;
        f.write_all(b).map_err(|e| Error::io(p, e))?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).map_err(|e| Error::io(p, e))?;
    }
    #[cfg(not(unix))]
    fs::write(p, b).map_err(|e| Error::io(p, e))?;
    Ok(())
}
