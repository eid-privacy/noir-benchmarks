//! Human-readable CBOR diagnostic formatting (for logging / debugging).

use ciborium::Value as CborValue;

/// Pretty-print CBOR values for logs (not wire-accurate; diagnostic only).
pub trait CborDisplay {
    fn is_scalar(&self) -> bool;
    fn scalar_repr(&self) -> String;
    fn pretty(&self) -> String;
}

impl CborDisplay for CborValue {
    fn is_scalar(&self) -> bool {
        matches!(
            self,
            CborValue::Integer(_)
                | CborValue::Bytes(_)
                | CborValue::Float(_)
                | CborValue::Text(_)
                | CborValue::Bool(_)
                | CborValue::Null
        )
    }

    fn scalar_repr(&self) -> String {
        match self {
            CborValue::Integer(v) => format!("{v:?}"),
            CborValue::Bytes(v) => format!("h'{}' ({} bytes)", hex::encode(v), v.len()),
            CborValue::Float(v) => format!("{v}"),
            CborValue::Text(v) => format!("\"{v}\""),
            CborValue::Bool(v) => format!("{v}"),
            CborValue::Null => "null".to_string(),
            CborValue::Tag(tag, nested) => format!("tag({tag}) {}", nested.scalar_repr()),
            CborValue::Array(_) | CborValue::Map(_) => "<non-scalar>".to_string(),
            _ => format!("{self:?}"),
        }
    }

    fn pretty(&self) -> String {
        let mut out = String::new();
        write_cbor_pretty(self, 0, &mut out);
        out
    }
}

fn write_cbor_value(value: &CborValue, indent: usize, out: &mut String) {
    if value.is_scalar() {
        out.push_str(&value.scalar_repr());
    } else {
        write_cbor_pretty(value, indent, out);
    }
}

fn write_cbor_pretty(value: &CborValue, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    let inner_pad = " ".repeat(indent + 2);
    match value {
        CborValue::Map(entries) => {
            out.push_str("{\n");
            for (idx, (key, val)) in entries.iter().enumerate() {
                out.push_str(&inner_pad);
                let key_repr = if key.is_scalar() {
                    key.scalar_repr()
                } else {
                    format!("{key:?}")
                };
                out.push_str(&key_repr);
                out.push_str(": ");
                write_cbor_value(val, indent + 2, out);
                if idx + 1 != entries.len() {
                    out.push('\n');
                }
            }
            out.push('\n');
            out.push_str(&pad);
            out.push('}');
        }
        CborValue::Array(values) => {
            out.push_str("[\n");
            for (idx, val) in values.iter().enumerate() {
                out.push_str(&inner_pad);
                write_cbor_value(val, indent + 2, out);
                if idx + 1 != values.len() {
                    out.push('\n');
                }
            }
            out.push('\n');
            out.push_str(&pad);
            out.push(']');
        }
        CborValue::Tag(tag, nested) => {
            out.push_str(&format!("tag({tag}) "));
            write_cbor_value(nested, indent, out);
        }
        _ => out.push_str(&value.scalar_repr()),
    }
}
