use crate::{
    auth::{format_time, Role, TrustStore},
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
        let p = trust
            .get(&signer)
            .ok_or_else(|| Error::authz("untrusted control signer"))?;
        if p.role != Role::Full {
            return Err(Error::authz("guests cannot send control"));
        }
        signer.verify("control", &unsigned(self)?, &self.sig)?;
        let at = parse_control_time(&self.at)?;
        if now.saturating_sub(at) > 300_000 || at > now + 60_000 {
            return Err(Error::authz("control timestamp outside window"));
        }
        trust.consume_control_nonce(&self.nonce, now)
    }
}
fn parse_control_time(s: &str) -> Result<u64> {
    // Reuse enrollment validation without exposing its parser: convert the
    // canonical UTC fields with a small, dependency-free civil-date routine.
    if s.len() != 24 {
        return Err(Error::protocol("bad control time"));
    }
    let n = |a, b| {
        s[a..b]
            .parse::<i64>()
            .map_err(|_| Error::protocol("bad control time"))
    };
    let (y, m, d, h, mi, se, ms) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
        n(20, 23)?,
    );
    let y0 = y - i64::from(m <= 2);
    let era = if y0 >= 0 { y0 } else { y0 - 399 } / 400;
    let yoe = y0 - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + (153 * mp + 2) / 5 + d - 1 - 719468;
    u64::try_from((days * 86400 + h * 3600 + mi * 60 + se) * 1000 + ms)
        .map_err(|_| Error::protocol("bad control time"))
}
