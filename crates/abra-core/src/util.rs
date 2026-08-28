//! Small shared helpers: hex, time.

use crate::error::{Error, Result};

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
}
