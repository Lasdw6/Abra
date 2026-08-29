use crate::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_CONTROL_FRAME: usize = 16 * 1024 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    let bytes = abra_core::canonical::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME {
        return Err(Error::protocol("control frame length outside 1..=16 MiB"));
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    let len = r.read_u32().await? as usize;
    if len == 0 || len > MAX_CONTROL_FRAME {
        return Err(Error::protocol("control frame length outside 1..=16 MiB"));
    }
    let mut bytes = vec![0; len];
    r.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn read_frame_timeout<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
    timeout: std::time::Duration,
) -> Result<T> {
    tokio::time::timeout(timeout, read_frame(r))
        .await
        .map_err(|_| Error::Timeout)?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    Blob = 1,
    Tree = 2,
}

impl TryFrom<u8> for ObjectKind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Blob),
            2 => Ok(Self::Tree),
            _ => Err(Error::protocol("unknown object kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectHeader {
    pub kind: ObjectKind,
    pub digest: abra_core::cas::Hash,
    pub total_size: u64,
    pub offset: u64,
}

impl ObjectHeader {
    pub const LEN: usize = 49;
    pub fn encode(self) -> [u8; Self::LEN] {
        let mut out = [0; Self::LEN];
        out[0] = self.kind as u8;
        out[1..33].copy_from_slice(self.digest.as_bytes());
        out[33..41].copy_from_slice(&self.total_size.to_be_bytes());
        out[41..49].copy_from_slice(&self.offset.to_be_bytes());
        out
    }
    pub fn decode(bytes: [u8; Self::LEN]) -> Result<Self> {
        let total_size = u64::from_be_bytes(bytes[33..41].try_into().expect("fixed"));
        let offset = u64::from_be_bytes(bytes[41..49].try_into().expect("fixed"));
        if offset > total_size {
            return Err(Error::protocol("object offset exceeds size"));
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[1..33]);
        Ok(Self {
            kind: bytes[0].try_into()?,
            digest: abra_core::cas::Hash::from_bytes(digest),
            total_size,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn framed_json_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let send = tokio::spawn(async move {
            write_frame(&mut a, &serde_json::json!({"type":"ping"}))
                .await
                .unwrap()
        });
        let got: serde_json::Value = read_frame(&mut b).await.unwrap();
        send.await.unwrap();
        assert_eq!(got["type"], "ping");
    }
}
