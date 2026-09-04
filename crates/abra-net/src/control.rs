use crate::{
    auth::{format_time, parse_time, Role, TrustStore},
    Error, Result,
};
use abra_core::{
    canonical,
    cas::Hash,
    identity::{Identity, PeerId, Signature},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub capsule_id: Hash,
    pub op: ControlOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub at: String,
    pub nonce: String,
    pub sig: Signature,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlAck {
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whatever the receiver's `ControlHandler` returned. `ControlAck` denies
    /// unknown fields, so this key is only serialized when the dialer's hello
    /// advertised `control-result`; older peers get an ack shaped as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// Receiver-side hook for acting on a verified control message. The daemon
/// registers one on its `DeliveryNode`; abra-net never interprets the message
/// itself. The returned value is sent back in `ControlAck.result`, but only if
/// the dialer advertised the `control-result` feature — the handler always runs
/// either way. An `Err` becomes `ok: false` plus `error` on the ack, and a
/// handler that runs longer than `CONTROL_HANDLER_TIMEOUT` is abandoned.
#[async_trait::async_trait]
pub trait ControlHandler: Send + Sync {
    async fn handle(&self, from: PeerId, message: &ControlMessage) -> Result<serde_json::Value>;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlOp {
    Pause,
    Stop,
    Instruct,
}

fn unsigned(x: &ControlMessage) -> Result<Vec<u8>> {
    let mut v = serde_json::to_value(x)?;
    v.as_object_mut().expect("object").remove("sig");
    Ok(canonical::to_vec(&v)?)
}
impl ControlMessage {
    pub fn new(
        capsule_id: Hash,
        op: ControlOp,
        text: Option<String>,
        at_ms: u64,
        nonce: [u8; 16],
        id: &Identity,
    ) -> Result<Self> {
        if (op == ControlOp::Instruct) != text.is_some() {
            return Err(Error::protocol("text must appear exactly for instruct"));
        }
        let mut x = Self {
            message_type: "control".into(),
            capsule_id,
            op,
            text,
            at: format_time(at_ms),
            nonce: hex::encode(nonce),
            sig: Signature::from_bytes([0; 64]),
        };
        x.sig = id.sign("control", &unsigned(&x)?);
        Ok(x)
    }
    pub fn verify_and_record(
        &self,
        signer: PeerId,
        trust: &mut TrustStore,
        now: u64,
    ) -> Result<()> {
        if self.message_type != "control" || (self.op == ControlOp::Instruct) != self.text.is_some()
        {
            return Err(Error::protocol("invalid control message"));
        }
        if self.text.as_ref().is_some_and(|x| x.len() > 8192) {
            return Err(Error::protocol("control text too large"));
        }
        if self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::protocol("invalid control nonce"));
        }
        let p = trust
            .get(&signer)
            .ok_or_else(|| Error::authz("untrusted control signer"))?;
        if p.role != Role::Full {
            return Err(Error::authz("guests cannot send control"));
        }
        signer.verify("control", &unsigned(self)?, &self.sig)?;
        let at = parse_time(&self.at)?;
        if now.saturating_sub(at) > 300_000 || at > now + 60_000 {
            return Err(Error::authz("control timestamp outside window"));
        }
        trust.consume_control_nonce(&self.nonce, now)
    }
}
