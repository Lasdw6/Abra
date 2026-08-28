//! Device identity: Ed25519 keypairs, peer ids, signing and verification.
//!
//! A peer is a keypair. A [`PeerId`] is the first 8 bytes of
//! `blake3(public_key)` — a short handle for display and indexing. The full
//! public key travels alongside it and is what verification actually uses, so
//! the short id is never load-bearing.
//!
//! "Only my devices" is an authorization policy layered on top of this (see
//! [`crate::enroll`]), not a property of the key format.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::hex_newtype;

/// Short handle for a peer: first 8 bytes of `blake3(public_key)`, hex encoded.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 8]);
hex_newtype!(PeerId, 8, "peer id");

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; 32]);
hex_newtype!(PublicKey, 32, "public key");

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);
hex_newtype!(Signature, 64, "signature");

impl PublicKey {
    /// Derive this key's [`PeerId`].
    pub fn peer_id(&self) -> PeerId {
        let digest = blake3::hash(&self.0);
        let mut short = [0u8; 8];
        short.copy_from_slice(&digest.as_bytes()[..8]);
        PeerId(short)
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| Error::encoding("public key", format!("not a valid ed25519 point: {e}")))
    }

    /// Verify a domain-separated signature (see [`domain_message`]).
    pub fn verify(&self, domain: &str, payload: &[u8], sig: &Signature) -> Result<()> {
        self.verify_raw(&domain_message(domain, payload), sig)
    }

    /// Verify a signature over exactly these bytes.
    ///
    /// Prefer [`PublicKey::verify`]; every signature Abra itself produces is
    /// domain separated.
    pub fn verify_raw(&self, message: &[u8], sig: &Signature) -> Result<()> {
        let vk = self.verifying_key()?;
        vk.verify(message, &ed25519_dalek::Signature::from_bytes(&sig.0))
            .map_err(|e| Error::BadSignature(e.to_string()))
    }
}

/// Bind a signature to a purpose: `domain || 0x00 || payload`.
///
/// Without this, a signature made for one Abra object could be replayed as a
/// signature for another.
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
        write!(f, "Identity({})", self.peer_id())
    }
}

/// On-disk key file. The secret is stored in the clear at mode 0600; phase 1
/// has no passphrase or keychain integration.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    abra_spec: u32,
    kind: String,
    peer_id: PeerId,
    public_key: PublicKey,
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

    /// This identity's public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// This identity's short peer id.
    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }

    /// Sign a domain-separated payload (see [`domain_message`]).
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
            abra_spec: crate::ABRA_SPEC,
            kind: KEYFILE_KIND.to_string(),
            peer_id: self.peer_id(),
            public_key: self.public_key(),
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

        if file.abra_spec != crate::ABRA_SPEC {
            return Err(Error::UnsupportedSpec {
                found: file.abra_spec,
                expected: crate::ABRA_SPEC,
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

        if identity.public_key() != file.public_key {
            return Err(Error::corrupt(
                "key file",
                "public key does not match secret key",
            ));
        }
        if identity.peer_id() != file.peer_id {
            return Err(Error::corrupt(
                "key file",
                "peer id does not match public key",
            ));
        }

        Ok(identity)
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
    fn peer_id_is_blake3_prefix_of_pubkey() {
        let id = Identity::generate();
        let pk = id.public_key();
        let digest = blake3::hash(pk.as_bytes());
        assert_eq!(pk.peer_id().as_bytes(), &digest.as_bytes()[..8]);
        assert_eq!(pk.peer_id().to_hex().len(), 16);
    }

    #[test]
    fn peer_id_display_and_fromstr_roundtrip() {
        let id = Identity::generate().peer_id();
        assert_eq!(PeerId::from_str(&id.to_string()).unwrap(), id);
        assert!(PeerId::from_str("nothex").is_err());
        assert!(PeerId::from_str("00112233").is_err(), "wrong length");
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        id.public_key()
            .verify("abra.test.v1", b"hello", &sig)
            .unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        assert!(id
            .public_key()
            .verify("abra.test.v1", b"hell0", &sig)
            .is_err());
    }

    #[test]
    fn verify_rejects_other_domain() {
        let id = Identity::generate();
        let sig = id.sign("abra.test.v1", b"hello");
        assert!(id
            .public_key()
            .verify("abra.other.v1", b"hello", &sig)
            .is_err());
    }

    #[test]
    fn verify_rejects_other_key() {
        let a = Identity::generate();
        let b = Identity::generate();
        let sig = a.sign("abra.test.v1", b"hello");
        assert!(b
            .public_key()
            .verify("abra.test.v1", b"hello", &sig)
            .is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("device.key");
        let id = Identity::generate();
        id.save(&path).unwrap();

        let loaded = Identity::load(&path).unwrap();
        assert_eq!(loaded.public_key(), id.public_key());
        assert_eq!(loaded.peer_id(), id.peer_id());
        assert_eq!(loaded.secret_bytes(), id.secret_bytes());
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
    fn load_rejects_mismatched_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        Identity::generate().save(&path).unwrap();

        let mut file: KeyFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file.public_key = Identity::generate().public_key();
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(Identity::load(&path).is_err());
    }

    #[test]
    fn load_rejects_unknown_spec_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        Identity::generate().save(&path).unwrap();

        let mut file: KeyFile = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        file.abra_spec = 99;
        fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        assert!(matches!(
            Identity::load(&path),
            Err(Error::UnsupportedSpec { found: 99, .. })
        ));
    }

    #[test]
    fn domain_message_is_separated_by_nul() {
        assert_eq!(domain_message("ab", b"cd"), b"ab\0cd");
    }

    #[test]
    fn identity_debug_does_not_leak_secret() {
        let id = Identity::generate();
        let shown = format!("{id:?}");
        assert!(!shown.contains(&crate::util::hex_encode(&id.secret_bytes())));
        assert!(shown.contains(&id.peer_id().to_hex()));
    }
}
