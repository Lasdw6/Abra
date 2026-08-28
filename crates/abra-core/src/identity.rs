//! Device identity: Ed25519 keypairs, peer ids, signing and verification.
//!
//! See `SPEC.md` §1.3.
//!
//! A peer *is* a keypair, so a [`PeerId`] *is* the Ed25519 public key — 32
//! bytes, lowercase hex. Nothing has to be looked up to verify a signature from
//! a peer id, because the peer id is the verification key.
//!
//! [`ShortId`] is the display handle: the first 8 bytes of `blake3(peer_id)`,
//! 16 hex characters. It is never load-bearing — verification is always against
//! the full key.
//!
//! "Only my devices" is an authorization policy layered on top of this, not a
//! property of the key format (DESIGN §7).

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::hex_newtype;

/// A peer: an Ed25519 public key, 32 bytes, lowercase hex (64 chars).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);
hex_newtype!(PeerId, 32, "peer id");

/// A peer's display handle: first 8 bytes of `blake3(peer_id)`, hex (16 chars).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortId([u8; 8]);
hex_newtype!(ShortId, 8, "short id");

/// An Ed25519 signature, 64 bytes, lowercase hex (128 chars).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);
hex_newtype!(Signature, 64, "signature");

impl PeerId {
    /// This peer's short display handle. See [`ShortId`].
    pub fn short(&self) -> ShortId {
        let digest = blake3::hash(&self.0);
        let mut short = [0u8; 8];
        short.copy_from_slice(&digest.as_bytes()[..8]);
        ShortId(short)
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| Error::encoding("peer id", format!("not a valid ed25519 point: {e}")))
    }

    /// Whether these bytes are a usable Ed25519 verification key.
    ///
    /// A peer id is parsed from hex before it is ever used to verify anything,
    /// so a syntactically fine but mathematically invalid key is possible and
    /// worth being able to reject early.
    pub fn is_valid_key(&self) -> bool {
        self.verifying_key().is_ok()
    }

    /// Verify a domain-separated signature. See [`domain_message`].
    pub fn verify(&self, domain: &str, payload: &[u8], sig: &Signature) -> Result<()> {
        self.verify_raw(&domain_message(domain, payload), sig)
    }

    /// Verify a signature over exactly these bytes.
    ///
    /// Prefer [`PeerId::verify`]; every signature Abra itself produces is domain
    /// separated.
    pub fn verify_raw(&self, message: &[u8], sig: &Signature) -> Result<()> {
        let vk = self.verifying_key()?;
        vk.verify(message, &ed25519_dalek::Signature::from_bytes(&sig.0))
            .map_err(|e| Error::BadSignature(e.to_string()))
    }
}

/// Bind a signature to a purpose: `domain || 0x00 || payload`.
///
/// Without this, a signature made for one Abra object could be replayed as a
/// signature for another. See `SPEC.md` §1.4.
pub fn domain_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 1 + payload.len());
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    out
}

/// A device's keypair: the secret half of a peer.
pub struct Identity {
    signing: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        write!(f, "Identity({})", self.short_id())
    }
}

/// On-disk key file. The secret is stored in the clear at mode 0600; phase 1
/// has no passphrase or keychain integration.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    spec: String,
    kind: String,
    peer_id: PeerId,
    short_id: ShortId,
    secret_key: String,
}

const KEYFILE_KIND: &str = "abra.identity";

impl Identity {
    /// Generate a fresh keypair from the OS RNG.
    pub fn generate() -> Self {
        Identity {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstruct from a 32-byte Ed25519 secret scalar seed.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Identity {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte secret seed. Handle accordingly.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// This identity's peer id, i.e. its public key.
    pub fn peer_id(&self) -> PeerId {
        PeerId(self.signing.verifying_key().to_bytes())
    }

    /// This identity's short display handle.
    pub fn short_id(&self) -> ShortId {
        self.peer_id().short()
    }

    /// Sign a domain-separated payload. See [`domain_message`].
    pub fn sign(&self, domain: &str, payload: &[u8]) -> Signature {
        self.sign_raw(&domain_message(domain, payload))
    }

    /// Sign exactly these bytes. Prefer [`Identity::sign`].
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        Signature(self.signing.sign(message).to_bytes())
    }

    /// Write the key file, creating parent directories, with mode 0600.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
        }

        let file = KeyFile {
            spec: crate::SPEC.to_string(),
            kind: KEYFILE_KIND.to_string(),
            peer_id: self.peer_id(),
            short_id: self.short_id(),
            secret_key: crate::util::hex_encode(&self.secret_bytes()),
        };
        let mut bytes = crate::canonical::to_vec(&file)?;
        bytes.push(b'\n');

        write_private(path, &bytes)
    }

    /// Read a key file written by [`Identity::save`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
        let file: KeyFile = serde_json::from_slice(&bytes)?;

        if file.spec != crate::SPEC {
            return Err(Error::UnsupportedSpec {
                found: file.spec,
                expected: crate::SPEC.to_string(),
            });
        }
        if file.kind != KEYFILE_KIND {
            return Err(Error::corrupt(
                "key file",
                format!("kind is {:?}, expected {KEYFILE_KIND:?}", file.kind),
            ));
        }

        let secret = crate::util::hex_decode_fixed::<32>(&file.secret_key, "secret key")?;
        let identity = Identity::from_secret_bytes(&secret);

        if identity.peer_id() != file.peer_id {
            return Err(Error::corrupt(
                "key file",
                "peer id does not match secret key",
            ));
        }
        if identity.short_id() != file.short_id {
            return Err(Error::corrupt(
                "key file",
                "short id does not match peer id",
            ));
        }

        Ok(identity)
    }

    /// Load the key file at `path`, generating and saving one if it is absent.
    ///
    /// This is what a daemon does at startup: a device's identity should exist
    /// after the first run and never change after that.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match Identity::load(path) {
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                let identity = Identity::generate();
                identity.save(path)?;
                Ok(identity)
            }
            other => other,
        }
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    f.write_all(bytes).map_err(|e| Error::io(path, e))?;
    // `mode` only applies at creation; re-assert for pre-existing files.
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| Error::io(path, e))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|e| Error::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn peer_id_is_the_ed25519_public_key() {
        let id = Identity::generate();
        let peer = id.peer_id();
        assert_eq!(peer.to_hex().len(), 64);
        assert!(peer.is_valid_key());

        // Deriving the key independently from the secret seed must agree.
        let expected = ed25519_dalek::SigningKey::from_bytes(&id.secret_bytes())
            .verifying_key()
            .to_bytes();
        assert_eq!(peer.as_bytes(), &expected);
    }

    #[test]
    fn short_id_is_the_blake3_prefix_of_the_peer_id() {
        let peer = Identity::generate().peer_id();
        let digest = blake3::hash(peer.as_bytes());
        assert_eq!(peer.short().as_bytes(), &digest.as_bytes()[..8]);
        assert_eq!(peer.short().to_hex().len(), 16);
    }

    #[test]
    fn peer_id_display_and_fromstr_roundtrip() {
        let peer = Identity::generate().peer_id();
        assert_eq!(PeerId::from_str(&peer.to_string()).unwrap(), peer);
        assert!(PeerId::from_str("nothex").is_err());
        assert!(PeerId::from_str("00112233").is_err(), "wrong length");
    }

    #[test]
    fn a_peer_id_nobody_holds_the_secret_for_verifies_nothing() {
        // Ed25519 accepts most 32-byte strings as decompressible points, so a
        // made-up peer id may well parse. What must never happen is a signature
        // verifying against it.
        let peer = PeerId::from_bytes([0xff; 32]);
        assert!(peer
            .verify_raw(b"x", &Signature::from_bytes([0; 64]))
            .is_err());

        let sig = Identity::generate().sign("abra.test.v1", b"hello");
        assert!(peer.verify("abra.test.v1", b"hello", &sig).is_err());
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        id.peer_id().verify("abra.test.v1", b"hello", &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        assert!(id.peer_id().verify("abra.test.v1", b"hell0", &sig).is_err());
    }

    #[test]
    fn verify_rejects_another_domain() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        assert!(id
            .peer_id()
            .verify("abra.other.v1", b"hello", &sig)
            .is_err());
    }

    #[test]
    fn verify_rejects_another_key() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = a.sign("abra.test.v1", b"hello");
        assert!(b.peer_id().verify("abra.test.v1", b"hello", &sig).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("device.key");
        let id = Identity::generate();
        id.save(&path).unwrap();

        let loaded = Identity::load(&path).unwrap();
        assert_eq!(loaded.peer_id(), id.peer_id());
        assert_eq!(loaded.short_id(), id.short_id());
        assert_eq!(loaded.secret_bytes(), id.secret_bytes());

        // A signature made before the round trip still verifies after it.
        let sig = id.sign("abra.test.v1", b"payload");
        loaded
            .peer_id()
            .verify("abra.test.v1", b"payload", &sig)
            .unwrap();
    }

    #[test]
    fn load_or_generate_creates_once_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");

        let first = Identity::load_or_generate(&path).unwrap();
        assert!(path.is_file());
        let second = Identity::load_or_generate(&path).unwrap();
        assert_eq!(first.peer_id(), second.peer_id());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        Identity::generate().save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn overwriting_a_loose_key_file_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        fs::write(&path, b"placeholder").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        Identity::generate().save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    #[test]
    fn load_rejects_a_peer_id_that_does_not_match_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        Identity::generate().save(&path).unwrap();

        let mut file: KeyFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file.peer_id = Identity::generate().peer_id();
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(Identity::load(&path), Err(Error::Corrupt { .. })));
    }

    #[test]
    fn load_rejects_an_unknown_spec_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        Identity::generate().save(&path).unwrap();

        let mut file: KeyFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file.spec = "99.0".into();
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(
            Identity::load(&path),
            Err(Error::UnsupportedSpec { .. })
        ));
    }

    #[test]
    fn domain_message_is_separated_by_nul() {
        assert_eq!(domain_message("ab", b"cd"), b"ab\0cd");
    }

    #[test]
    fn identity_debug_does_not_leak_the_secret() {
        let id = Identity::generate();
        let shown = format!("{id:?}");
        assert!(!shown.contains(&crate::util::hex_encode(&id.secret_bytes())));
        assert!(shown.contains(&id.short_id().to_hex()));
    }
}
