//! Blind-relay discovery tags and recipient-sealed envelopes.
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const DAY_MS: i64 = 86_400_000;
const MAGIC: &[u8; 8] = b"ABRAREL1";

pub fn day_tag(discovery_key: &[u8; 32], epoch_day: i64) -> [u8; 32] {
    hmac_sha256(
        discovery_key,
        &[
            b"abra-relay-tag-v1\0".as_slice(),
            epoch_day.to_be_bytes().as_slice(),
        ]
        .concat(),
    )
}
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= block[i];
        outer[i] ^= block[i];
    }
    let inner_hash = Sha256::digest([inner.as_slice(), message].concat());
    Sha256::digest([outer.as_slice(), inner_hash.as_slice()].concat()).into()
}
pub fn polling_tags(discovery_key: &[u8; 32], now_ms: u64) -> [[u8; 32]; 3] {
    let day = (now_ms as i64) / DAY_MS;
    [
        day_tag(discovery_key, day - 1),
        day_tag(discovery_key, day),
        day_tag(discovery_key, day + 1),
    ]
}
pub fn seal(recipient_public: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient_public));
    let key = Sha256::digest(
        [
            b"abra-relay-seal-v1\0".as_slice(),
            shared.as_bytes(),
            epk.as_bytes(),
            &recipient_public,
        ]
        .concat(),
    );
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut aad = Vec::from(MAGIC);
    aad.extend_from_slice(epk.as_bytes());
    aad.extend_from_slice(&recipient_public);
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .expect("SHA-256 key")
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::protocol("relay sealing failed"))?;
    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
pub fn open(recipient_secret: [u8; 32], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < 8 + 32 + 32 + 12 + 16 || &envelope[..8] != MAGIC {
        return Err(Error::protocol("invalid relay sealed envelope"));
    }
    let secret = StaticSecret::from(recipient_secret);
    let recipient = PublicKey::from(&secret);
    if envelope[40..72] != recipient.to_bytes() {
        return Err(Error::Authentication(
            "relay envelope recipient mismatch".into(),
        ));
    }
    let epk: [u8; 32] = envelope[8..40].try_into().expect("length checked");
    let shared = secret.diffie_hellman(&PublicKey::from(epk));
    let key = Sha256::digest(
        [
            b"abra-relay-seal-v1\0".as_slice(),
            shared.as_bytes(),
            &epk,
            &recipient.to_bytes(),
        ]
        .concat(),
    );
    Aes256Gcm::new_from_slice(&key)
        .expect("SHA-256 key")
        .decrypt(
            Nonce::from_slice(&envelope[72..84]),
            Payload {
                msg: &envelope[84..],
                aad: &envelope[..72],
            },
        )
        .map_err(|_| Error::Authentication("relay envelope authentication failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tags_cover_adjacent_days_and_sealed_roundtrip_is_opaque() {
        let key = [7; 32];
        let tags = polling_tags(&key, DAY_MS as u64 * 4);
        assert_eq!(tags[1], day_tag(&key, 4));
        let secret = StaticSecret::random_from_rng(OsRng).to_bytes();
        let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        let sealed = seal(public, b"private manifest").unwrap();
        assert!(!sealed.windows(16).any(|x| x == b"private manifest"));
        assert_eq!(open(secret, &sealed).unwrap(), b"private manifest");
        assert!(open([3; 32], &sealed).is_err());
    }
}
