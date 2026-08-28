use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

const MAX_TITLE_CHARS: usize = 512;
const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
const MAX_TLS_SUBJECT_CHARS: usize = 4_096;
const MAX_JSON_DEPTH: usize = 16;

static TITLE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<title(?:\s[^>]*)?>(.*?)</title>").expect("title regex is valid")
});
static HTML_TAG_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("html tag regex is valid"));

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SearchContent {
    pub(crate) title: Option<String>,
    pub(crate) http_body: Option<String>,
    pub(crate) http_body_truncated: bool,
    pub(crate) tls_subject: Option<String>,
}

pub(crate) fn extract_search_content(data: Option<&Value>) -> SearchContent {
    let Some(data) = data else {
        return SearchContent::default();
    };
    let body = find_string_by_key(data, &["body"], 0).map(|value| value.to_owned());
    let (http_body, http_body_truncated) = body
        .map(|value| truncate_utf8_bytes(&value, MAX_HTTP_BODY_BYTES))
        .map(|(value, truncated)| (Some(value), truncated))
        .unwrap_or((None, false));
    let title = http_body
        .as_deref()
        .and_then(extract_html_title)
        .or_else(|| find_string_by_key(data, &["title"], 0).map(clean_text))
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_TITLE_CHARS).collect());
    let tls_subject = find_value_by_key(data, &["subject_dn", "subjectDN", "subject"], 0)
        .and_then(value_as_text)
        .map(|value| value.chars().take(MAX_TLS_SUBJECT_CHARS).collect())
        .filter(|value: &String| !value.is_empty());

    SearchContent {
        title,
        http_body,
        http_body_truncated,
        tls_subject,
    }
}

fn find_string_by_key<'a>(value: &'a Value, keys: &[&str], depth: usize) -> Option<&'a str> {
    find_value_by_key(value, keys, depth).and_then(Value::as_str)
}

fn find_value_by_key<'a>(value: &'a Value, keys: &[&str], depth: usize) -> Option<&'a Value> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key)
                    && !found.is_null()
                {
                    return Some(found);
                }
            }
            map.values()
                .find_map(|child| find_value_by_key(child, keys, depth + 1))
        }
        Value::Array(items) => items
            .iter()
            .find_map(|child| find_value_by_key(child, keys, depth + 1)),
        _ => None,
    }
}

fn value_as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(clean_text(value)),
        Value::Object(_) | Value::Array(_) => serde_json::to_string(value).ok(),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => None,
    }
}

fn extract_html_title(body: &str) -> Option<String> {
    let captures = TITLE_PATTERN.captures(body)?;
    let inner = captures.get(1)?.as_str();
    let without_tags = HTML_TAG_PATTERN.replace_all(inner, " ");
    let title = clean_text(&without_tags);
    (!title.is_empty()).then_some(title)
}

fn clean_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_owned(), false);
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{MAX_HTTP_BODY_BYTES, extract_search_content};

    #[test]
    fn extracts_http_title_body_and_tls_subject_from_probe_evidence() {
        let data = json!({
            "evidence": [
                {
                    "module": "https",
                    "result": {
                        "response": {"body": "<html><title> Hikvision  Camera </title></html>"}
                    }
                },
                {
                    "module": "tls",
                    "result": {"handshake_log": {"server_certificates": {"subject_dn": "CN=camera.example"}}}
                }
            ]
        });

        let content = extract_search_content(Some(&data));
        assert_eq!(content.title.as_deref(), Some("Hikvision Camera"));
        assert!(content.http_body.as_deref().unwrap().contains("<html>"));
        assert_eq!(content.tls_subject.as_deref(), Some("CN=camera.example"));
        assert!(!content.http_body_truncated);
    }

    #[test]
    fn truncates_large_bodies_on_a_utf8_boundary() {
        let body = format!("{}界", "a".repeat(MAX_HTTP_BODY_BYTES));
        let data = json!({"response": {"body": body}});
        let content = extract_search_content(Some(&data));

        assert_eq!(content.http_body.unwrap().len(), MAX_HTTP_BODY_BYTES);
        assert!(content.http_body_truncated);
    }

    #[test]
    fn empty_or_unrelated_data_yields_no_search_content() {
        assert_eq!(extract_search_content(None), Default::default());
        assert_eq!(
            extract_search_content(Some(&json!({"status": "success"}))),
            Default::default()
        );
    }
}
