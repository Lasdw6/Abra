use crate::{AdapterError, InspectResult, InventoryReport, Result};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) const MAX_LINE: usize = 1024 * 1024;

/// Build one `abra-adapter/1` request object.
///
/// Sets `protocol`, a fresh hex `request_id`, and `verb`. `body` must be a JSON
/// object; extra fields are kept. The serialized line must be at most 1 MiB.
pub fn build_request(verb: &str, body: Value) -> Result<(String, Value)> {
    let Value::Object(mut fields) = body else {
        return Err("adapter request body must be an object".into());
    };
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    let request_id = hex::encode(id);
    fields.insert("protocol".into(), json!("abra-adapter/1"));
    fields.insert("request_id".into(), json!(request_id));
    fields.insert("verb".into(), json!(verb));
    let request = Value::Object(fields);
    let line = serde_json::to_vec(&request)?;
    if line.len() > MAX_LINE {
        return Err("adapter request exceeds 1 MiB".into());
    }
    Ok((request_id, request))
}

/// Parse one `abra-adapter/1` response line for `verb` / `request_id`.
///
/// Enforces the 1 MiB cap, matching `request_id`, `ok:true`, and the same
/// per-verb normalisation `invoke` uses.
pub fn parse_response(verb: &str, request_id: &str, line: &str) -> Result<Value> {
    if line.len() > MAX_LINE {
        return Err("adapter response exceeds 1 MiB".into());
    }
    let response: Value =
        serde_json::from_str(line).map_err(|e| format!("malformed adapter output: {e}"))?;
    if response.get("request_id").and_then(Value::as_str) != Some(request_id) {
        return Err("adapter response request_id mismatch".into());
    }
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        let error: AdapterErrorBody = serde_json::from_value(
            response
                .get("error")
                .cloned()
                .ok_or("adapter failure response lacks error")?,
        )?;
        return Err(Box::new(AdapterError {
            code: error.code,
            message: error.message,
            retryable: error.retryable,
        }) as Box<dyn std::error::Error + Send + Sync>);
    }
    let mut fields = response
        .as_object()
        .cloned()
        .ok_or("adapter response must be an object")?;
    fields.remove("request_id");
    fields.remove("ok");
    let value = Value::Object(fields);
    match verb {
        "export" => {
            if !value.get("payload").is_some_and(Value::is_object) {
                return Err("adapter export response requires an object payload".into());
            }
            Ok(value)
        }
        "import" => {
            let result = value
                .get("result")
                .cloned()
                .ok_or("adapter import response requires result")?;
            let mut import = json!({"result": result});
            if let Some(deep_link) = value.get("deep_link") {
                if !deep_link.is_null() {
                    import["deep_link"] = deep_link.clone();
                }
            }
            Ok(import)
        }
        "control" => value
            .get("result")
            .cloned()
            .ok_or_else(|| format!("adapter {verb} response requires result").into()),
        "inspect" => {
            if value.get("result").is_some() {
                return Err("adapter inspect response must use flat fields".into());
            }
            Ok(serde_json::to_value(serde_json::from_value::<
                InspectResult,
            >(value)?)?)
        }
        "preview" => {
            let media_type = value.get("media_type").and_then(Value::as_str);
            if !matches!(media_type, Some("image/jpeg" | "image/png" | "image/webp")) {
                return Err("adapter preview response requires media_type image/jpeg, image/png, or image/webp".into());
            }
            if !value.get("data").is_some_and(Value::is_string) {
                return Err("adapter preview response requires base64 data".into());
            }
            if !(value.get("width").is_some_and(Value::is_u64)
                && value.get("height").is_some_and(Value::is_u64))
            {
                return Err("adapter preview response requires width and height".into());
            }
            if let Some(items) = value.get("items") {
                let items = items
                    .as_array()
                    .ok_or("adapter preview items must be an array")?;
                if items.len() > 64
                    || items
                        .iter()
                        .any(|i| !i.get("label").is_some_and(Value::is_string))
                {
                    return Err("adapter preview items need a label each, at most 64".into());
                }
            }
            Ok(value)
        }
        "inventory" => Ok(serde_json::to_value(serde_json::from_value::<
            InventoryReport,
        >(value)?)?),
        _ => Err(format!("unsupported adapter response verb: {verb}").into()),
    }
}

#[derive(Debug, Deserialize)]
struct AdapterErrorBody {
    code: String,
    message: String,
    retryable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_sets_envelope_and_keeps_body_fields() {
        let (id, request) =
            build_request("export", json!({"kind": "com.test", "source": "x"})).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(request["protocol"], json!("abra-adapter/1"));
        assert_eq!(request["request_id"], json!(id));
        assert_eq!(request["verb"], json!("export"));
        assert_eq!(request["kind"], json!("com.test"));
        assert_eq!(request["source"], json!("x"));
        assert!(serde_json::to_vec(&request).unwrap().len() <= MAX_LINE);
    }

    #[test]
    fn build_request_overwrites_caller_envelope_fields() {
        let (id, request) = build_request(
            "inspect",
            json!({"protocol": "other", "request_id": "nope", "verb": "export"}),
        )
        .unwrap();
        assert_eq!(request["protocol"], json!("abra-adapter/1"));
        assert_eq!(request["request_id"], json!(id));
        assert_eq!(request["verb"], json!("inspect"));
        assert_ne!(id, "nope");
    }

    #[test]
    fn build_request_rejects_a_non_object_body() {
        let error = build_request("export", json!("x")).unwrap_err();
        assert!(error.to_string().contains("object"));
        let error = build_request("export", json!([1])).unwrap_err();
        assert!(error.to_string().contains("object"));
    }

    #[test]
    fn build_request_rejects_a_line_over_one_mib() {
        let huge = "x".repeat(MAX_LINE);
        let error = build_request("export", json!({"data": huge})).unwrap_err();
        assert!(error.to_string().contains("1 MiB"));
    }

    fn ok_line(request_id: &str, extra: &str) -> String {
        format!(r#"{{"request_id":"{request_id}","ok":true,{extra}}}"#)
    }

    #[test]
    fn parse_response_export_requires_an_object_payload() {
        let value = parse_response(
            "export",
            "ab",
            &ok_line("ab", r#""payload":{"k":1},"files_path":null"#),
        )
        .unwrap();
        assert_eq!(value["payload"], json!({"k": 1}));
        assert_eq!(value["files_path"], json!(null));
        let error =
            parse_response("export", "ab", &ok_line("ab", r#""payload":"nope""#)).unwrap_err();
        assert!(error.to_string().contains("object payload"));
    }

    #[test]
    fn parse_response_import_normalizes_result_and_optional_deep_link() {
        let value = parse_response(
            "import",
            "ab",
            &ok_line(
                "ab",
                r#""result":{"ok":true},"deep_link":"abra://x","extra":1"#,
            ),
        )
        .unwrap();
        assert_eq!(value, json!({"result":{"ok":true},"deep_link":"abra://x"}));
        let value = parse_response(
            "import",
            "ab",
            &ok_line("ab", r#""result":1,"deep_link":null"#),
        )
        .unwrap();
        assert_eq!(value, json!({"result": 1}));
        let error =
            parse_response("import", "ab", &ok_line("ab", r#""deep_link":"x""#)).unwrap_err();
        assert!(error.to_string().contains("requires result"));
    }

    #[test]
    fn parse_response_control_returns_result() {
        let value =
            parse_response("control", "ab", &ok_line("ab", r#""result":{"op":"stop"}"#)).unwrap();
        assert_eq!(value, json!({"op": "stop"}));
        let error = parse_response("control", "ab", &ok_line("ab", r#""other":true"#)).unwrap_err();
        assert!(error.to_string().contains("requires result"));
    }

    #[test]
    fn parse_response_inventory_validates_items_and_limit() {
        let value = parse_response("inventory", "ab", &ok_line("ab", r#""label":"Browser","items":[{"id":"tab-1","kind":"com.test","label":"Example","source":{"tab":"1"},"transferable":true}]"#)).unwrap();
        assert_eq!(value["items"][0]["id"], "tab-1");
        let items = (0..257).map(|i| json!({"id":i.to_string(),"kind":"com.test","label":"x","source":{},"transferable":true})).collect::<Vec<_>>();
        let line = json!({"request_id":"ab","ok":true,"label":"x","items":items}).to_string();
        assert!(parse_response("inventory", "ab", &line)
            .unwrap_err()
            .to_string()
            .contains("256"));
    }

    #[test]
    fn parse_response_inspect_uses_flat_fields() {
        let value = parse_response(
            "inspect",
            "ab",
            &ok_line("ab", r#""summary":"1 files","warnings":[],"blocked":[]"#),
        )
        .unwrap();
        assert_eq!(
            value,
            json!({"summary":"1 files","warnings":[],"blocked":[]})
        );
        let error = parse_response(
            "inspect",
            "ab",
            &ok_line("ab", r#""result":{"summary":"x"}"#),
        )
        .unwrap_err();
        assert!(error.to_string().contains("flat fields"));
    }

    #[test]
    fn parse_response_maps_adapter_errors_and_rejects_mismatches() {
        let error = parse_response(
            "export",
            "ab",
            r#"{"request_id":"ab","ok":false,"error":{"code":"busy","message":"try later","retryable":true}}"#,
        )
        .unwrap_err();
        let adapter_error = error.downcast_ref::<AdapterError>().unwrap();
        assert_eq!(adapter_error.code, "busy");
        assert_eq!(adapter_error.message, "try later");
        assert!(adapter_error.retryable);
        assert_eq!(adapter_error.to_string(), "busy: try later");

        let error =
            parse_response("export", "want", &ok_line("other", r#""payload":{}"#)).unwrap_err();
        assert!(error.to_string().contains("request_id mismatch"));
        let error = parse_response("export", "ab", "not json\n").unwrap_err();
        assert!(error.to_string().contains("malformed"));
        let error = parse_response("watch", "ab", &ok_line("ab", r#""payload":{}"#)).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported adapter response verb"));
    }

    #[test]
    fn parse_response_rejects_a_line_over_one_mib() {
        let line = "x".repeat(MAX_LINE + 1);
        let error = parse_response("export", "ab", &line).unwrap_err();
        assert!(error.to_string().contains("1 MiB"));
    }
}
