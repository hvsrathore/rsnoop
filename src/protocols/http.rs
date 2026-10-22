//! Hypertext Transfer Protocol (HTTP/1.0 and HTTP/1.1) parser.
//!
//! Defined in RFC 7230 / RFC 9112, HTTP is an application layer request/response protocol.
//! This module uses `httparse` to safely parse HTTP headers and extract key metadata
//! like methods, paths, status codes, Host, and User-Agent.

use std::collections::HashMap;

/// Decoded HTTP packet: either a Request or a Response.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum HttpInfo {
    /// HTTP Client Request (e.g. GET /index.html).
    Request(HttpRequestInfo),
    /// HTTP Server Response (e.g. 200 OK).
    Response(HttpResponseInfo),
}

/// Information parsed from an HTTP Request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpRequestInfo {
    /// Request method (e.g. "GET", "POST", "PUT", "DELETE", "HEAD").
    pub method: String,
    /// Requested resource URI / path (e.g. "/api/v1/users").
    pub path: String,
    /// HTTP minor version (0 for HTTP/1.0, 1 for HTTP/1.1).
    pub version: u8,
    /// Value of the "Host" header.
    pub host: Option<String>,
    /// Value of the "User-Agent" header.
    pub user_agent: Option<String>,
    /// Content-Type header if present.
    pub content_type: Option<String>,
    /// Content-Length header if present.
    pub content_length: Option<usize>,
    /// All parsed headers as key-value pairs.
    pub headers: HashMap<String, String>,
}

/// Information parsed from an HTTP Response.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpResponseInfo {
    /// HTTP minor version.
    pub version: u8,
    /// Numeric status code (e.g. 200, 301, 404, 500).
    pub code: u16,
    /// Textual reason phrase (e.g. "OK", "Not Found").
    pub reason: String,
    /// Value of the "Server" header.
    pub server: Option<String>,
    /// Content-Type header if present.
    pub content_type: Option<String>,
    /// Content-Length header if present.
    pub content_length: Option<usize>,
    /// All parsed headers as key-value pairs.
    pub headers: HashMap<String, String>,
}

impl HttpInfo {
    /// Returns a concise one-line summary of the HTTP request or response.
    pub fn summary(&self) -> String {
        match self {
            HttpInfo::Request(req) => {
                let host_str = req
                    .host
                    .as_deref()
                    .map(|h| format!(" [Host: {}]", h))
                    .unwrap_or_default();
                format!("HTTP {} {}{}", req.method, req.path, host_str)
            }
            HttpInfo::Response(resp) => {
                let ct_str = resp
                    .content_type
                    .as_deref()
                    .map(|ct| format!(" [{}]", ct))
                    .unwrap_or_default();
                format!("HTTP/1.{} {} {}{}", resp.version, resp.code, resp.reason, ct_str)
            }
        }
    }
}

/// Parses raw application layer data into an [`HttpInfo`] structure.
///
/// # Arguments
/// * `slice` - TCP payload data bytes.
///
/// # Returns
/// `Some(HttpInfo)` if the bytes match an HTTP request or response format.
pub fn parse_http(slice: &[u8]) -> Option<HttpInfo> {
    if slice.is_empty() {
        return None;
    }

    // Quick verification of common HTTP request method prefixes
    let starts_with_method = slice.starts_with(b"GET ")
        || slice.starts_with(b"POST ")
        || slice.starts_with(b"PUT ")
        || slice.starts_with(b"DELETE ")
        || slice.starts_with(b"HEAD ")
        || slice.starts_with(b"OPTIONS ")
        || slice.starts_with(b"CONNECT ")
        || slice.starts_with(b"PATCH ");

    // Quick verification of HTTP response status line prefix
    let starts_with_resp = slice.starts_with(b"HTTP/1.0 ") || slice.starts_with(b"HTTP/1.1 ");

    if !starts_with_method && !starts_with_resp {
        return None;
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];

    // Try parsing as HTTP Request
    if starts_with_method {
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(_) | httparse::Status::Partial) = req.parse(slice) {
            if let (Some(method), Some(path)) = (req.method, req.path) {
                let mut header_map = HashMap::new();
                let mut host = None;
                let mut user_agent = None;
                let mut content_type = None;
                let mut content_length = None;

                for h in req.headers {
                    let name = h.name.to_lowercase();
                    let val = String::from_utf8_lossy(h.value).to_string();
                    match name.as_str() {
                        "host" => host = Some(val.clone()),
                        "user-agent" => user_agent = Some(val.clone()),
                        "content-type" => content_type = Some(val.clone()),
                        "content-length" => content_length = val.parse().ok(),
                        _ => {}
                    }
                    header_map.insert(name, val);
                }

                return Some(HttpInfo::Request(HttpRequestInfo {
                    method: method.to_string(),
                    path: path.to_string(),
                    version: req.version.unwrap_or(1),
                    host,
                    user_agent,
                    content_type,
                    content_length,
                    headers: header_map,
                }));
            }
        }
    }

    // Try parsing as HTTP Response
    if starts_with_resp {
        let mut resp = httparse::Response::new(&mut headers);
        if let Ok(httparse::Status::Complete(_) | httparse::Status::Partial) = resp.parse(slice) {
            if let Some(code) = resp.code {
                let reason = resp.reason.unwrap_or("").to_string();
                let mut header_map = HashMap::new();
                let mut server = None;
                let mut content_type = None;
                let mut content_length = None;

                for h in resp.headers {
                    let name = h.name.to_lowercase();
                    let val = String::from_utf8_lossy(h.value).to_string();
                    match name.as_str() {
                        "server" => server = Some(val.clone()),
                        "content-type" => content_type = Some(val.clone()),
                        "content-length" => content_length = val.parse().ok(),
                        _ => {}
                    }
                    header_map.insert(name, val);
                }

                return Some(HttpInfo::Response(HttpResponseInfo {
                    version: resp.version.unwrap_or(1),
                    code,
                    reason,
                    server,
                    content_type,
                    content_length,
                    headers: header_map,
                }));
            }
        }
    }

    None
}
