//! `transports/` replay: QR envelopes (static + animated) and serial request
//! frames round-tripped through `nsealr-core`'s transport codecs, asserting the
//! vector's `payload_base64url`, `decoded`, digest, and framing exactly.

use super::{arr_field, assert_json_eq, frame_type_from_str, str_field, ReplayResult};
use nsealr_core::base64url::{decode_base64url, encode_base64url, encoded_len};
use nsealr_core::hash::sha256_hex;
use nsealr_core::qr::envelope::{
    decode_animated_qr_envelope_frames, decode_qr_envelope, encode_animated_qr_envelope_json,
    encode_qr_envelope_json, parse_qr_signing_request, PREFIX,
};
use nsealr_core::qr::limits::{
    MAX_ANIMATED_QR_DECODED_JSON_BYTES, MAX_SERIAL_FRAME_BYTES, MAX_STATIC_QR_DECODED_JSON_BYTES,
};
use nsealr_core::serial::frame::{decode_serial_frame, encode_serial_frame};
use serde_json::Value;

pub(super) fn replay(value: &Value) -> ReplayResult {
    match str_field(value, "format")? {
        "qr-envelope-v0" => replay_static_envelope(value),
        "qr-animated-envelope-v0" => replay_animated_envelope(value),
        "serial-frame-v0" => replay_serial_frame(value),
        other => Err(format!("unknown transports format '{other}'")),
    }
}

fn replay_static_envelope(value: &Value) -> ReplayResult {
    let envelope = str_field(value, "envelope")?.as_bytes();
    let payload_b64 = str_field(value, "payload_base64url")?.as_bytes();
    let decoded = value.get("decoded").ok_or("missing 'decoded'")?;

    let mut json_buf = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
    let env = decode_qr_envelope(envelope, &mut json_buf)
        .map_err(|e| format!("decode_qr_envelope: {e:?}"))?;
    if env.payload_base64url != payload_b64 {
        return Err("decoded payload_base64url != vector.payload_base64url".into());
    }
    let got: Value = serde_json::from_slice(env.payload_json)
        .map_err(|e| format!("parse decoded payload json: {e}"))?;
    assert_json_eq("static envelope decoded", &got, decoded)?;

    // The envelope carries a signing request: it must parse end-to-end.
    parse_qr_signing_request(env.payload_json)
        .map_err(|e| format!("parse_qr_signing_request over decoded payload: {e:?}"))?;

    // base64url round-trips exactly.
    let mut pbuf = vec![0u8; encoded_len(env.payload_json.len())];
    let re_b64 = encode_base64url(env.payload_json, &mut pbuf)
        .map_err(|e| format!("encode_base64url: {e:?}"))?;
    if re_b64 != payload_b64 {
        return Err("re-encoded base64url != vector.payload_base64url".into());
    }
    // Envelope re-encodes byte-for-byte.
    let mut ebuf = vec![0u8; PREFIX.len() + encoded_len(env.payload_json.len())];
    let re_env = encode_qr_envelope_json(env.payload_json, &mut ebuf)
        .map_err(|e| format!("encode_qr_envelope_json: {e:?}"))?;
    if re_env != envelope {
        return Err("re-encoded envelope != vector.envelope".into());
    }
    Ok(())
}

fn replay_animated_envelope(value: &Value) -> ReplayResult {
    let payload_b64 = str_field(value, "payload_base64url")?.as_bytes();
    let digest_hex = str_field(value, "decoded_json_sha256")?;
    let chunk_size = value
        .get("chunk_size_chars")
        .and_then(Value::as_u64)
        .ok_or("missing/!int 'chunk_size_chars'")? as usize;
    let decoded = value.get("decoded").ok_or("missing 'decoded'")?;
    let frames_json = arr_field(value, "frames")?;
    let frame_bufs: Vec<Vec<u8>> = frames_json
        .iter()
        .map(|f| {
            f.as_str()
                .map(|s| s.as_bytes().to_vec())
                .ok_or_else(|| "frame entry not a string".to_string())
        })
        .collect::<Result<_, _>>()?;
    let frame_refs: Vec<&[u8]> = frame_bufs.iter().map(Vec::as_slice).collect();

    let mut payload_buf = vec![0u8; encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)];
    let mut json_buf = vec![0u8; MAX_ANIMATED_QR_DECODED_JSON_BYTES];
    let env = decode_animated_qr_envelope_frames(&frame_refs, &mut payload_buf, &mut json_buf)
        .map_err(|e| format!("decode_animated_qr_envelope_frames: {e:?}"))?;
    if env.payload_base64url != payload_b64 {
        return Err("animated payload_base64url != vector.payload_base64url".into());
    }
    let got: Value = serde_json::from_slice(env.payload_json)
        .map_err(|e| format!("parse animated decoded json: {e}"))?;
    assert_json_eq("animated envelope decoded", &got, decoded)?;

    // The whole-payload digest matches the vector's declared sha256.
    let digest = sha256_hex(env.payload_json);
    if digest.as_slice() != digest_hex.as_bytes() {
        return Err(format!(
            "decoded_json_sha256 mismatch: got {}, want {digest_hex}",
            core::str::from_utf8(&digest).unwrap_or("<non-utf8>")
        ));
    }

    // The frames re-encode byte-for-byte at the declared chunk size.
    let mut re_frames: Vec<Vec<u8>> = Vec::new();
    encode_animated_qr_envelope_json(env.payload_json, chunk_size, &mut |frame, _, _| {
        re_frames.push(frame.to_vec());
    })
    .map_err(|e| format!("encode_animated_qr_envelope_json: {e:?}"))?;
    if re_frames != frame_bufs {
        return Err("re-encoded animated frames != vector.frames".into());
    }
    Ok(())
}

fn replay_serial_frame(value: &Value) -> ReplayResult {
    let frame = str_field(value, "frame")?.as_bytes();
    let payload_b64 = str_field(value, "payload_base64url")?.as_bytes();
    let type_token = str_field(value, "type")?;
    let decoded = value.get("decoded").ok_or("missing 'decoded'")?;
    let expected_type = frame_type_from_str(type_token)?;

    let sf = decode_serial_frame(frame).map_err(|e| format!("decode_serial_frame: {e:?}"))?;
    if sf.frame_type != expected_type {
        return Err(format!(
            "frame type {:?} != vector.type {type_token}",
            sf.frame_type
        ));
    }
    if sf.payload_base64url != payload_b64 {
        return Err("serial payload_base64url != vector.payload_base64url".into());
    }
    let mut json_buf = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
    let json = decode_base64url(sf.payload_base64url, &mut json_buf)
        .map_err(|e| format!("decode serial payload: {e:?}"))?;
    let got: Value =
        serde_json::from_slice(json).map_err(|e| format!("parse serial decoded json: {e}"))?;
    assert_json_eq("serial frame decoded", &got, decoded)?;

    // Frame (including checksum) re-encodes byte-for-byte.
    let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
    let re_frame = encode_serial_frame(expected_type, payload_b64, &mut buf)
        .map_err(|e| format!("encode_serial_frame: {e:?}"))?;
    if re_frame != frame {
        return Err("re-encoded serial frame != vector.frame".into());
    }
    Ok(())
}
