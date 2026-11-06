//! Minimal `https://` URL parsing for doctor and, later, the NC client.
//!
//! A crate is deliberately avoided here: the surface is small and the plan
//! keeps dependencies minimal. Credentials in the authority are refused because
//! they must never be passed in a URL.

use std::fmt;

use crate::error::ProtoError;

/// A parsed HTTP(S) URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Lower-case scheme (`https` or `http`).
    pub scheme: String,
    /// Host without IPv6 brackets.
    pub host: String,
    /// Explicit or default port.
    pub port: u16,
    /// Path plus query string, always starting with `/`.
    pub path_and_query: String,
}

impl Url {
    /// Parse an absolute URL.
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ProtoError::InvalidUrl("URL is empty".into()));
        }

        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| ProtoError::InvalidUrl("missing scheme".into()))?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            other => {
                return Err(ProtoError::InvalidUrl(format!(
                    "unsupported scheme '{other}'; expected https"
                )))
            }
        };

        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(ProtoError::InvalidUrl("missing host".into()));
        }
        if authority.contains('@') {
            return Err(ProtoError::InvalidUrl(
                "credentials in a URL are not allowed".into(),
            ));
        }

        let (host, port) = split_authority(authority, default_port)?;
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(ProtoError::InvalidUrl("missing or invalid host".into()));
        }

        let mut path = &rest[authority_end..];
        if let Some(fragment_start) = path.find('#') {
            path = &path[..fragment_start];
        }
        let path_and_query = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };

        Ok(Self {
            scheme,
            host,
            port,
            path_and_query,
        })
    }

    /// Whether this URL uses TLS.
    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    /// Resolve a `Location` reference against this URL.
    ///
    /// Supports absolute URLs, scheme-relative URLs, root-relative paths,
    /// document-relative paths and query/fragment-only references. Dot
    /// segments are normalised. The fragment is dropped because HTTP requests
    /// never carry it.
    pub fn join(&self, reference: &str) -> Result<Url, ProtoError> {
        let reference = reference.trim();
        if reference.is_empty() {
            return Ok(self.clone());
        }
        if reference.contains("://") {
            return Url::parse(reference);
        }
        if reference.starts_with("//") {
            return Url::parse(&format!("{}:{reference}", self.scheme));
        }

        let reference = reference.split('#').next().unwrap_or_default();
        let base_path = self
            .path_and_query
            .split('?')
            .next()
            .filter(|path| !path.is_empty())
            .unwrap_or("/");

        let (path, query) = if let Some(query) = reference.strip_prefix('?') {
            (base_path.to_owned(), Some(query))
        } else {
            let (raw_path, query) = match reference.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (reference, None),
            };
            let path = if raw_path.starts_with('/') {
                raw_path.to_owned()
            } else {
                let directory = match base_path.rfind('/') {
                    Some(index) => &base_path[..=index],
                    None => "/",
                };
                format!("{directory}{raw_path}")
            };
            (normalize_path(&path), query)
        };

        let path_and_query = match query {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        Ok(Url {
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            port: self.port,
            path_and_query,
        })
    }

    /// Value for the HTTP `Host` header, bracketing IPv6 literals.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.is_https() { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme,
            self.host_header(),
            self.path_and_query
        )
    }
}

fn normalize_path(path: &str) -> String {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    let mut normalized = String::from("/");
    normalized.push_str(&segments.join("/"));
    if path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), ProtoError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| ProtoError::InvalidUrl("unterminated IPv6 literal".into()))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else if let Some(port) = after.strip_prefix(':') {
            parse_port(port)?
        } else {
            return Err(ProtoError::InvalidUrl(
                "unexpected characters after IPv6 literal".into(),
            ));
        };
        return Ok((host.to_owned(), port));
    }

    let colon_count = authority.bytes().filter(|byte| *byte == b':').count();
    match (colon_count, authority.rsplit_once(':')) {
        (0, _) => Ok((authority.to_owned(), default_port)),
        (1, Some((host, port))) => Ok((host.to_owned(), parse_port(port)?)),
        _ => Err(ProtoError::InvalidUrl(
            "IPv6 literals must be enclosed in brackets".into(),
        )),
    }
}

fn parse_port(port: &str) -> Result<u16, ProtoError> {
    if port.is_empty() {
        return Err(ProtoError::InvalidUrl("empty port".into()));
    }
    port.parse::<u16>()
        .map_err(|_| ProtoError::InvalidUrl(format!("invalid port '{port}'")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_https() {
        let url = Url::parse("https://vpn.example.net").expect("url");
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "vpn.example.net");
        assert_eq!(url.port, 443);
        assert_eq!(url.path_and_query, "/");
        assert_eq!(url.host_header(), "vpn.example.net");
        assert!(url.is_https());
    }

    #[test]
    fn parses_path_port_and_query() {
        let url = Url::parse("https://example.net:8443/example_realm?x=1#frag").expect("url");
        assert_eq!(url.host, "example.net");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path_and_query, "/example_realm?x=1");
        assert_eq!(url.host_header(), "example.net:8443");
    }

    #[test]
    fn query_without_path_gets_a_slash() {
        let url = Url::parse("https://example.net?x=1").expect("url");
        assert_eq!(url.path_and_query, "/?x=1");
    }

    #[test]
    fn parses_ipv6_literals() {
        let url = Url::parse("https://[2001:db8::1]:8443/login").expect("url");
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 8443);
        assert_eq!(url.host_header(), "[2001:db8::1]:8443");

        let default = Url::parse("https://[2001:db8::1]/").expect("url");
        assert_eq!(default.host_header(), "[2001:db8::1]");
    }

    #[test]
    fn rejects_credentials_schemes_and_garbage() {
        for input in [
            "https://user:pass@example.net/",
            "ftp://example.net/",
            "example.net/login",
            "https://",
            "https:///path",
            "https://example.net:notaport/",
            "https://2001:db8::1/",
            "https://example.net:/",
        ] {
            assert!(Url::parse(input).is_err(), "{input} must be rejected");
        }
    }

    #[test]
    fn http_is_parsed_but_not_https() {
        let url = Url::parse("http://example.net/health").expect("url");
        assert!(!url.is_https());
        assert_eq!(url.port, 80);
        assert_eq!(url.host_header(), "example.net");
    }

    #[test]
    fn joins_redirect_locations() {
        let base = Url::parse("https://example.net/example_realm/index.html?x=1").expect("url");

        for (reference, expected) in [
            ("https://other.example.org/a", "https://other.example.org/a"),
            ("//other.example.org/a", "https://other.example.org/a"),
            (
                "/dana-na/auth/welcome.cgi",
                "https://example.net/dana-na/auth/welcome.cgi",
            ),
            ("login.cgi", "https://example.net/example_realm/login.cgi"),
            ("../login.cgi", "https://example.net/login.cgi"),
            (
                "?realm=example_realm",
                "https://example.net/example_realm/index.html?realm=example_realm",
            ),
            ("/a/b/../c#frag", "https://example.net/a/c"),
        ] {
            assert_eq!(
                base.join(reference).expect("join").to_string(),
                expected,
                "reference {reference}"
            );
        }
    }
}
