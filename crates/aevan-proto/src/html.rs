//! A small, dependency-free HTML form scraper.
//!
//! The Network Connect login flow needs only enough HTML understanding to find
//! `<form>` elements and their `<input>` fields: `frmLogin`, the hidden `realm`
//! field, and the secondary-token page (`frmTotpToken` / `password#2`). A DOM
//! library would be disproportionate here, so this module scans tags directly.
//!
//! The scanner is deliberately forgiving. It lower-cases names, ignores HTML
//! comments, decodes the handful of entities that appear in `action` values and
//! never executes or renders anything.

use crate::error::ProtoError;
use crate::url::Url;

/// One `<input>` element found inside a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormInput {
    /// `name` attribute.
    pub name: Option<String>,
    /// `value` attribute.
    pub value: Option<String>,
    /// `type` attribute, lower-cased.
    pub input_type: Option<String>,
    /// `id` attribute.
    pub id: Option<String>,
    /// Whether `disabled` is present.
    pub disabled: bool,
}

impl FormInput {
    /// Whether this is a hidden input.
    pub fn is_hidden(&self) -> bool {
        self.type_is("hidden")
    }

    /// Whether the input type matches `value` (case-insensitive).
    pub fn type_is(&self, value: &str) -> bool {
        self.input_type
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(value))
    }
}

/// One `<form>` element with the inputs it contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// `action` attribute, if present.
    pub action: Option<String>,
    /// `method` attribute, lower-cased; defaults to `get`.
    pub method: String,
    /// `enctype` attribute, lower-cased.
    pub enctype: Option<String>,
    /// `id` attribute.
    pub id: Option<String>,
    /// `name` attribute.
    pub name: Option<String>,
    /// Contained `<input>` elements in document order.
    pub inputs: Vec<FormInput>,
}

impl Form {
    /// `id` or `name`, whichever is present, for form-shape detection.
    pub fn name_or_id(&self) -> Option<&str> {
        self.id.as_deref().or(self.name.as_deref())
    }

    /// Whether an input with the exact name exists.
    pub fn has_input(&self, name: &str) -> bool {
        self.inputs
            .iter()
            .any(|input| input.name.as_deref() == Some(name))
    }

    /// The name of the first input matching any candidate, case-insensitively.
    pub fn input_name(&self, candidates: &[&str]) -> Option<String> {
        self.inputs.iter().find_map(|input| {
            let name = input.name.as_deref()?;
            candidates
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
                .then(|| name.to_owned())
        })
    }

    /// The value of an input with the exact name.
    pub fn input_value(&self, name: &str) -> Option<&str> {
        self.inputs
            .iter()
            .find(|input| input.name.as_deref() == Some(name))
            .and_then(|input| input.value.as_deref())
    }

    /// Whether this form carries the hidden `realm` field.
    pub fn has_realm_field(&self) -> bool {
        self.inputs.iter().any(|input| {
            input
                .name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("realm"))
                || input
                    .id
                    .as_deref()
                    .is_some_and(|id| id.eq_ignore_ascii_case("realm"))
        })
    }

    /// Whether this is the classic `frmLogin` form.
    pub fn is_login_form(&self) -> bool {
        self.name_or_id()
            .is_some_and(|value| value.eq_ignore_ascii_case("frmLogin"))
    }

    /// Whether this form has a password input.
    pub fn has_password_field(&self) -> bool {
        self.inputs.iter().any(|input| input.type_is("password"))
    }

    /// Whether this form is the secondary-token challenge.
    ///
    /// The observed vendor markers are the form name `frmTotpToken` and the
    /// input name `password#2`. A `totp` fragment in an input name is accepted
    /// as a third spelling. A CSRF field merely called `token` is not treated
    /// as the challenge, to avoid classifying an ordinary login page as a token
    /// page.
    pub fn has_token_field(&self) -> bool {
        if self
            .name_or_id()
            .is_some_and(|value| value.eq_ignore_ascii_case("frmTotpToken"))
        {
            return true;
        }
        self.inputs.iter().any(|input| {
            input.name.as_deref().is_some_and(|name| {
                name.eq_ignore_ascii_case("password#2")
                    || name.to_ascii_lowercase().contains("totp")
            })
        })
    }

    /// Name of the token input, preferring `password#2`.
    pub fn token_field_name(&self) -> Option<String> {
        self.input_name(&["password#2"])
            .or_else(|| {
                self.inputs.iter().find_map(|input| {
                    let name = input.name.as_deref()?;
                    name.to_ascii_lowercase()
                        .contains("totp")
                        .then(|| name.to_owned())
                })
            })
            .or_else(|| {
                self.inputs
                    .iter()
                    .find(|input| input.type_is("password"))
                    .and_then(|input| input.name.clone())
            })
    }

    /// Resolve `action` against the page URL. A missing or empty action means
    /// the current document URL.
    pub fn resolved_action(&self, base: &Url) -> Result<Url, ProtoError> {
        match self.action.as_deref().map(str::trim) {
            Some(action) if !action.is_empty() => base.join(action),
            _ => Ok(base.clone()),
        }
    }
}

/// Parse every `<form>` in `html`.
pub fn parse_forms(html: &str) -> Vec<Form> {
    let html = strip_comments(html);
    let mut forms = Vec::new();
    let mut cursor = 0;

    while let Some(start) = find_tag_start(&html, cursor, "form") {
        let Some(tag) = parse_tag(&html, start) else {
            cursor = start + 1;
            continue;
        };
        let content_start = tag.end;
        let content_end = find_tag_start(&html, content_start, "/form").unwrap_or(html.len());
        let inputs = parse_inputs(&html[content_start..content_end]);
        forms.push(tag.into_form(inputs));

        cursor = if content_end >= html.len() {
            html.len()
        } else {
            parse_tag(&html, content_end)
                .map(|closing| closing.end)
                .unwrap_or(content_end + 1)
        };
    }

    forms
}

/// Find the first `<input>` in `html` whose name is `name`.
pub fn find_input<'a>(forms: &'a [Form], name: &str) -> Option<&'a FormInput> {
    forms
        .iter()
        .flat_map(|form| form.inputs.iter())
        .find(|input| input.name.as_deref() == Some(name))
}

fn parse_inputs(html: &str) -> Vec<FormInput> {
    let mut inputs = Vec::new();
    let mut cursor = 0;

    while let Some(start) = find_tag_start(html, cursor, "input") {
        let Some(tag) = parse_tag(html, start) else {
            cursor = start + 1;
            continue;
        };
        inputs.push(FormInput {
            name: tag.attribute("name").map(str::to_owned),
            value: tag.attribute("value").map(str::to_owned),
            input_type: tag.attribute("type").map(str::to_ascii_lowercase),
            id: tag.attribute("id").map(str::to_owned),
            disabled: tag.attribute("disabled").is_some(),
        });
        cursor = tag.end;
    }

    inputs
}

struct RawTag {
    attributes: Vec<(String, String)>,
    end: usize,
}

impl RawTag {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn into_form(self, inputs: Vec<FormInput>) -> Form {
        Form {
            action: self.attribute("action").map(str::to_owned),
            method: self
                .attribute("method")
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| "get".to_owned()),
            enctype: self.attribute("enctype").map(str::to_ascii_lowercase),
            id: self.attribute("id").map(str::to_owned),
            name: self.attribute("name").map(str::to_owned),
            inputs,
        }
    }
}

fn parse_tag(html: &str, start: usize) -> Option<RawTag> {
    let end = find_tag_end(html, start + 1)?;
    let inner = html[start + 1..end].trim();
    let inner = inner.strip_suffix('/').unwrap_or(inner).trim();
    let name_end = inner
        .find(|character: char| character.is_ascii_whitespace() || character == '/')
        .unwrap_or(inner.len());
    let name = inner[..name_end].to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    let attributes = parse_attributes(&inner[name_end..]);
    Some(RawTag {
        attributes,
        end: end + 1,
    })
}

fn parse_attributes(input: &str) -> Vec<(String, String)> {
    let mut attributes = Vec::new();
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'='
            && bytes[index] != b'/'
        {
            index += 1;
        }
        if index == name_start {
            index += 1;
            continue;
        }
        let name = input[name_start..index].to_ascii_lowercase();

        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        let mut value = String::new();
        if index < bytes.len() && bytes[index] == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && (bytes[index] == b'"' || bytes[index] == b'\'') {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }
                value = decode_entities(&input[value_start..index]);
                if index < bytes.len() {
                    index += 1;
                }
            } else {
                let value_start = index;
                while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                    index += 1;
                }
                value = decode_entities(&input[value_start..index]);
            }
        }

        attributes.push((name, value));
    }

    attributes
}

fn find_tag_end(html: &str, from: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut quote = None;
    let mut index = from;

    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(current) => {
                if byte == current {
                    quote = None;
                }
            }
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'>' => return Some(index),
                _ => {}
            },
        }
        index += 1;
    }

    None
}

fn find_tag_start(html: &str, from: usize, name: &str) -> Option<usize> {
    let bytes = html.as_bytes();
    let needle = format!("<{name}");
    let needle = needle.as_bytes();
    let mut index = from;

    while index + needle.len() <= bytes.len() {
        if bytes[index..index + needle.len()].eq_ignore_ascii_case(needle) {
            let after = index + needle.len();
            if after >= bytes.len()
                || bytes[after].is_ascii_whitespace()
                || bytes[after] == b'>'
                || bytes[after] == b'/'
            {
                return Some(index);
            }
        }
        index += 1;
    }

    None
}

fn strip_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("<!--") {
        output.push_str(&rest[..start]);
        if let Some(end) = rest[start + 4..].find("-->") {
            rest = &rest[start + 4 + end + 3..];
        } else {
            rest = "";
        }
    }
    output.push_str(rest);
    output
}

fn decode_entities(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find(';').filter(|end| *end <= 10) else {
            output.push('&');
            rest = after;
            continue;
        };
        let entity = &after[..end];
        let decoded = match entity.to_ascii_lowercase().as_str() {
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "nbsp" => Some(' '),
            _ => None,
        };
        match decoded {
            Some(character) => {
                output.push(character);
                rest = &after[end + 1..];
            }
            None => {
                output.push('&');
                rest = after;
            }
        }
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_forms_actions_and_inputs() {
        let html = r#"
            <form id="frmLogin" action="login.cgi?x=1&amp;y=2" method="POST">
              <input type="hidden" name="realm" value="example_realm">
              <input name="username" value="">
              <input type="password" name="password">
              <input type="submit" value="Sign In">
            </form>
        "#;
        let forms = parse_forms(html);
        assert_eq!(forms.len(), 1);
        let form = &forms[0];
        assert!(form.is_login_form());
        assert_eq!(form.method, "post");
        assert_eq!(form.action.as_deref(), Some("login.cgi?x=1&y=2"));
        assert!(form.has_realm_field());
        assert_eq!(form.input_value("realm"), Some("example_realm"));
        assert!(form.has_password_field());
        assert_eq!(form.inputs.len(), 4);
    }

    #[test]
    fn detects_the_token_form() {
        let html = r#"
            <form id="frmTotpToken" action="/dana-na/auth/url_default/login.cgi" method="post">
              <input type="hidden" name="realm" value="example_realm">
              <input type="password" name="password#2">
            </form>
        "#;
        let forms = parse_forms(html);
        assert_eq!(forms.len(), 1);
        assert!(forms[0].has_token_field());
        assert_eq!(forms[0].token_field_name().as_deref(), Some("password#2"));
    }

    #[test]
    fn unquoted_attributes_and_relative_actions() {
        let html = "<form action=/example_realm/login.cgi method=post><input name=realm value=example_realm></form>";
        let forms = parse_forms(html);
        assert_eq!(forms[0].action.as_deref(), Some("/example_realm/login.cgi"));
        assert!(forms[0].has_realm_field());
    }

    #[test]
    fn handles_comments_quotes_and_uppercase() {
        let html = r#"
            <!-- <form id="frmFake"><input name="realm"></form> -->
            <FORM id="frmLogin" action="/a?b=c&amp;d=e" METHOD="POST">
              <INPUT TYPE="HIDDEN" NAME="realm" VALUE="example_realm">
            </FORM>
        "#;
        let forms = parse_forms(html);
        assert_eq!(forms.len(), 1);
        assert!(forms[0].is_login_form());
        assert_eq!(forms[0].action.as_deref(), Some("/a?b=c&d=e"));
        assert_eq!(forms[0].inputs[0].input_type.as_deref(), Some("hidden"));
    }

    #[test]
    fn a_page_without_forms_yields_nothing() {
        assert!(parse_forms("<html><body>404</body></html>").is_empty());
    }

    #[test]
    fn resolves_relative_actions() {
        let base = Url::parse("https://example.net/example_realm/").expect("url");
        let form = Form {
            action: Some("login.cgi".into()),
            method: "post".into(),
            enctype: None,
            id: Some("frmLogin".into()),
            name: None,
            inputs: vec![],
        };
        assert_eq!(
            form.resolved_action(&base).expect("resolve").to_string(),
            "https://example.net/example_realm/login.cgi"
        );
    }
}
