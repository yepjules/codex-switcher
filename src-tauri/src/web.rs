use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::Context;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use tokio::runtime::Runtime;

use crate::commands::{
    add_account_from_auth_json_text, cancel_login, check_codex_processes, complete_login,
    delete_account, export_accounts_full_encrypted_bytes, fetch_usage, get_account_usage_stats,
    get_active_account_info, get_masked_account_ids, import_accounts_full_encrypted_bytes,
    import_accounts_slim_text, kill_codex_processes, list_accounts, refresh_account_metadata,
    refresh_all_accounts_usage, rename_account, set_masked_account_ids, start_login,
    switch_account, warmup_account, warmup_all_accounts,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountIdArgs {
    #[serde(alias = "account_id")]
    account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameAccountArgs {
    #[serde(alias = "account_id")]
    account_id: String,
    #[serde(alias = "new_name")]
    new_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginArgs {
    #[serde(alias = "account_name")]
    account_name: String,
}

#[derive(Debug, Deserialize)]
struct ImportSlimArgs {
    payload: String,
}

#[derive(Debug, Deserialize)]
struct MaskedIdsArgs {
    ids: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseCodexArgs {
    reopen_desktop: Option<bool>,
    force_close: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UploadAuthJsonArgs {
    name: String,
    contents: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadEncryptedArgs {
    #[serde(alias = "contents_base64")]
    contents_base64: String,
    passphrase: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportEncryptedArgs {
    passphrase: String,
}

const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

/// Use the env override when set (validated), else generate 32 random bytes as base64url.
pub fn resolve_web_token(env_value: Option<String>) -> anyhow::Result<String> {
    match env_value {
        None => {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        }
        Some(value) => {
            // The token is printed into a URL fragment and sent back in an HTTP header,
            // so only unreserved URL characters survive both unchanged. The value is
            // never echoed in the error.
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
            {
                anyhow::bail!(
                    "CODEX_SWITCHER_WEB_TOKEN may only contain the characters A-Z a-z 0-9 . _ ~ - (no spaces, newlines or other symbols)"
                );
            }
            let distinct: HashSet<char> = value.chars().collect();
            if value.chars().count() < 32 || distinct.len() < 8 {
                anyhow::bail!(
                    "CODEX_SWITCHER_WEB_TOKEN must be at least 32 characters with at least 8 distinct characters"
                );
            }
            Ok(value)
        }
    }
}

fn find_header<'a>(headers: &'a [Header], name: &'static str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

/// Request gate: token (401) -> Origin (403) -> Content-Type (415).
/// The token is the control that defeats CSRF and DNS rebinding; the Origin
/// check is defense in depth only.
fn authorize(headers: &[Header], token: &str) -> Result<(), (u16, &'static str)> {
    let provided = find_header(headers, "Authorization")
        .and_then(|value| {
            let (scheme, rest) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
        })
        .ok_or((401, "unauthorized"))?;
    if !bool::from(provided.as_bytes().ct_eq(token.as_bytes())) {
        return Err((401, "unauthorized"));
    }

    if let Some(origin) = find_header(headers, "Origin") {
        let host = find_header(headers, "Host").ok_or((403, "forbidden origin"))?;
        let authority = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or((403, "forbidden origin"))?;
        if !authority.eq_ignore_ascii_case(host) {
            return Err((403, "forbidden origin"));
        }
    }

    let content_type = find_header(headers, "Content-Type").unwrap_or_default();
    if !content_type
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return Err((415, "content type must be application/json"));
    }

    Ok(())
}

fn read_body_limited(
    reader: impl Read,
    content_length: Option<usize>,
    max: usize,
) -> Result<Vec<u8>, (u16, &'static str)> {
    if content_length.is_some_and(|len| len > max) {
        return Err((413, "payload too large"));
    }
    let mut body = Vec::new();
    reader
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| (400, "failed to read request body"))?;
    if body.len() > max {
        return Err((413, "payload too large"));
    }
    Ok(body)
}

fn parse_json_body(bytes: &[u8]) -> Result<Value, (u16, &'static str)> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }
    serde_json::from_slice(bytes).map_err(|_| (400, "invalid JSON"))
}

fn static_security_headers() -> Vec<Header> {
    [
        ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
    ]
    .into_iter()
    .map(|(name, value)| header(name, value).expect("static header is valid"))
    .collect()
}

/// Number of threads that take requests off the shared queue. One slow or hostile
/// client then cannot hold up every other client.
const HANDLER_THREADS: usize = 4;

/// Formats `host:port` so `ToSocketAddrs` accepts IPv6 literals (`[::1]:3210`).
fn bind_address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Host to show in the startup URL: wildcard binds print `localhost`, IPv6 literals get brackets.
fn display_host(host: &str) -> (String, bool) {
    match host {
        "0.0.0.0" | "::" | "[::]" => ("localhost".to_string(), true),
        h if h.contains(':') && !h.starts_with('[') => (format!("[{h}]"), false),
        h => (h.to_string(), false),
    }
}

pub fn run_lan_server(host: &str, port: u16, token: String) -> anyhow::Result<()> {
    if let Err(err) = crate::auth::harden_config_permissions() {
        eprintln!("[Startup] Failed to harden config permissions: {err:#}");
    }
    let address = bind_address(host, port);
    let server = Server::http(&address)
        .map_err(|err| anyhow::anyhow!("Failed to bind HTTP server on {address}: {err}"))?;
    let runtime = Runtime::new().context("Failed to start async runtime")?;
    let dist_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("dist");

    println!("Codex Switcher web server listening on http://{address}");
    println!("Serving static files from {}", dist_dir.display());
    let (shown_host, wildcard) = display_host(host);
    println!("Open: http://{shown_host}:{port}/#token={token}");
    if wildcard {
        println!(
            "Listening on all interfaces — replace localhost with this machine's LAN or tailnet address"
        );
    }

    let workers = spawn_request_handlers(
        Arc::new(server),
        Arc::new(runtime),
        Arc::new(dist_dir),
        Arc::from(token),
        HANDLER_THREADS,
    );
    for worker in workers {
        let _ = worker.join();
    }

    Ok(())
}

/// Starts `count` threads that each pull requests from the shared server queue.
fn spawn_request_handlers(
    server: Arc<Server>,
    runtime: Arc<Runtime>,
    dist_dir: Arc<PathBuf>,
    token: Arc<str>,
    count: usize,
) -> Vec<JoinHandle<()>> {
    (0..count)
        .map(|_| {
            let (server, runtime, dist_dir, token) = (
                server.clone(),
                runtime.clone(),
                dist_dir.clone(),
                token.clone(),
            );
            std::thread::spawn(move || {
                for request in server.incoming_requests() {
                    if let Err(error) = handle_request(request, &runtime, &dist_dir, &token) {
                        eprintln!("[web] request failed: {error:#}");
                    }
                }
            })
        })
        .collect()
}

fn handle_request(
    mut request: Request,
    runtime: &Runtime,
    dist_dir: &Path,
    token: &str,
) -> anyhow::Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();

    if method == Method::Get && url == "/api/health" {
        respond_json(request, StatusCode(200), &json!({ "ok": true }))?;
        return Ok(());
    }

    if method == Method::Post && url.starts_with("/api/invoke/") {
        let command = url.trim_start_matches("/api/invoke/").to_string();
        if let Err((status, message)) = authorize(request.headers(), token) {
            return respond_error(request, status, message);
        }
        let content_length = request.body_length();
        let body = match read_body_limited(request.as_reader(), content_length, MAX_BODY_BYTES) {
            Ok(body) => body,
            Err((status, message)) => return respond_error(request, status, message),
        };
        let payload = match parse_json_body(&body) {
            Ok(payload) => payload,
            Err((status, message)) => return respond_error(request, status, message),
        };
        match runtime.block_on(invoke_web_command(&command, payload)) {
            Ok(value) => respond_json(request, StatusCode(200), &value)?,
            Err((status, message)) => respond_error(request, status, &message)?,
        }
        return Ok(());
    }

    if method == Method::Get {
        serve_static(request, dist_dir, &url)?;
        return Ok(());
    }

    respond_text(
        request,
        StatusCode(405),
        "Method Not Allowed",
        "text/plain; charset=utf-8",
    )?;
    Ok(())
}

enum CommandFailure {
    Unsupported(String),
    Failed(String),
}

impl From<String> for CommandFailure {
    fn from(message: String) -> Self {
        CommandFailure::Failed(message)
    }
}

async fn invoke_web_command(command: &str, payload: Value) -> Result<Value, (u16, String)> {
    dispatch_command(command, payload)
        .await
        .map_err(|failure| match failure {
            CommandFailure::Unsupported(message) => (404, message),
            CommandFailure::Failed(message) => (400, message),
        })
}

async fn dispatch_command(command: &str, payload: Value) -> Result<Value, CommandFailure> {
    let result: Result<Value, String> = match command {
        "list_accounts" => to_json(list_accounts().await?),
        "get_active_account_info" => to_json(get_active_account_info().await?),
        "add_account_from_auth_json_text" => {
            let args: UploadAuthJsonArgs = parse_args(payload)?;
            to_json(add_account_from_auth_json_text(args.name, args.contents).await?)
        }
        "get_usage" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(fetch_usage(&args.account_id).await?)
        }
        "get_account_usage_stats" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(get_account_usage_stats(args.account_id).await?)
        }
        "refresh_account_metadata" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(refresh_account_metadata(args.account_id).await?)
        }
        "refresh_all_accounts_usage" => to_json(refresh_all_accounts_usage().await?),
        "warmup_account" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(warmup_account(args.account_id).await?)
        }
        "warmup_all_accounts" => to_json(warmup_all_accounts().await?),
        "switch_account" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(switch_account(args.account_id).await?)
        }
        "delete_account" => {
            let args: AccountIdArgs = parse_args(payload)?;
            to_json(delete_account(args.account_id).await?)
        }
        "rename_account" => {
            let args: RenameAccountArgs = parse_args(payload)?;
            to_json(rename_account(args.account_id, args.new_name).await?)
        }
        "start_login" => {
            let args: LoginArgs = parse_args(payload)?;
            to_json(start_login(args.account_name).await?)
        }
        "complete_login" => to_json(complete_login().await?),
        "cancel_login" => to_json(cancel_login().await?),
        "import_accounts_slim_text" => {
            let args: ImportSlimArgs = parse_args(payload)?;
            to_json(import_accounts_slim_text(args.payload).await?)
        }
        "export_accounts_full_encrypted_bytes" => {
            let args: ExportEncryptedArgs = parse_args(payload)?;
            let encoded =
                STANDARD.encode(export_accounts_full_encrypted_bytes(args.passphrase).await?);
            to_json(encoded)
        }
        "import_accounts_full_encrypted_bytes" => {
            let args: UploadEncryptedArgs = parse_args(payload)?;
            let bytes = STANDARD
                .decode(args.contents_base64)
                .map_err(|error| format!("Failed to decode uploaded backup: {error}"))?;
            to_json(import_accounts_full_encrypted_bytes(bytes, args.passphrase).await?)
        }
        "get_masked_account_ids" => to_json(get_masked_account_ids().await?),
        "set_masked_account_ids" => {
            let args: MaskedIdsArgs = parse_args(payload)?;
            to_json(set_masked_account_ids(args.ids).await?)
        }
        "check_codex_processes" => to_json(check_codex_processes().await?),
        "kill_codex_processes" => {
            let args: CloseCodexArgs = parse_args(payload)?;
            to_json(kill_codex_processes(args.reopen_desktop, args.force_close).await?)
        }
        _ => {
            return Err(CommandFailure::Unsupported(format!(
                "Unsupported web command: {command}"
            )))
        }
    };
    result.map_err(CommandFailure::Failed)
}

fn parse_args<T>(value: Value) -> Result<T, String>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|error| format!("Invalid command payload: {error}"))
}

fn to_json<T>(value: T) -> Result<Value, String>
where
    T: serde::Serialize,
{
    serde_json::to_value(value).map_err(|error| format!("Failed to serialize response: {error}"))
}

fn serve_static(request: Request, dist_dir: &Path, url: &str) -> anyhow::Result<()> {
    let requested = if url == "/" {
        PathBuf::from("index.html")
    } else {
        match sanitize_path(url) {
            Ok(path) => path,
            Err(_) => return respond_not_found(request),
        }
    };
    let candidate = dist_dir.join(&requested);

    if candidate.is_file() {
        return serve_file(request, candidate);
    }

    if requested.extension().is_some() {
        return respond_not_found(request);
    }

    serve_file(request, dist_dir.join("index.html"))
}

fn respond_not_found(request: Request) -> anyhow::Result<()> {
    respond_text(
        request,
        StatusCode(404),
        "Not Found",
        "text/plain; charset=utf-8",
    )
}

fn sanitize_path(url: &str) -> anyhow::Result<PathBuf> {
    let path = url.split('?').next().unwrap_or("/");
    let raw = path.trim_start_matches('/');
    let candidate = Path::new(raw);

    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            _ => anyhow::bail!("Invalid request path"),
        }
    }

    Ok(candidate.to_path_buf())
}

fn serve_file(request: Request, path: PathBuf) -> anyhow::Result<()> {
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("[web] failed to read {}: {error}", path.display());
            return respond_not_found(request);
        }
    };
    let mime = mime_type_for_path(&path);
    let mut response = Response::from_data(data)
        .with_header(header("Content-Type", mime)?)
        .with_header(header("Cache-Control", "no-cache")?);
    for security_header in static_security_headers() {
        response.add_header(security_header);
    }
    request.respond(response)?;
    Ok(())
}

fn respond_json(request: Request, status: StatusCode, payload: &Value) -> anyhow::Result<()> {
    let response = Response::from_string(serde_json::to_string(payload)?)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json; charset=utf-8")?)
        .with_header(header("X-Content-Type-Options", "nosniff")?)
        .with_header(header("Cache-Control", "no-store")?);
    request.respond(response)?;
    Ok(())
}

fn respond_error(request: Request, status: u16, message: &str) -> anyhow::Result<()> {
    respond_json(request, StatusCode(status), &json!({ "error": message }))
}

fn respond_text(
    request: Request,
    status: StatusCode,
    body: &str,
    content_type: &str,
) -> anyhow::Result<()> {
    let mut response = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header("Content-Type", content_type)?);
    for security_header in static_security_headers() {
        response.add_header(security_header);
    }
    request.respond(response)?;
    Ok(())
}

fn header(name: &str, value: &str) -> anyhow::Result<Header> {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).map_err(|_| {
        anyhow::anyhow!("Failed to create header {name}: invalid header value `{value}`")
    })
}

fn mime_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "css" => "text/css; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "ico" => "image/x-icon",
        "jpeg" | "jpg" => "image/jpeg",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_support::TestHome;
    use std::io::Read;

    const T: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn h(name: &str, value: &str) -> Header {
        Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
    }

    fn auth() -> Header {
        h("Authorization", &format!("Bearer {T}"))
    }

    fn json_ct() -> Header {
        h("Content-Type", "application/json")
    }

    fn status(r: Result<(), (u16, &'static str)>) -> u16 {
        match r {
            Ok(()) => 0,
            Err((s, _)) => s,
        }
    }

    #[test]
    fn authorize_requires_token() {
        assert_eq!(status(authorize(&[json_ct()], T)), 401);
        assert_eq!(
            status(authorize(
                &[h("Authorization", "Bearer wrong"), json_ct()],
                T
            )),
            401
        );
        assert_eq!(status(authorize(&[auth(), json_ct()], T)), 0);
    }

    #[test]
    fn authorize_requires_json_content_type() {
        assert_eq!(
            status(authorize(&[auth(), h("Content-Type", "text/plain")], T)),
            415
        );
        assert_eq!(status(authorize(&[auth()], T)), 415);
    }

    #[test]
    fn authorize_checks_origin_against_host() {
        let base = || vec![auth(), json_ct()];
        let with = |extra: Vec<Header>| {
            let mut v = base();
            v.extend(extra);
            v
        };
        assert_eq!(
            status(authorize(
                &with(vec![
                    h("Origin", "http://evil.example"),
                    h("Host", "192.168.1.5:3210")
                ]),
                T
            )),
            403
        );
        assert_eq!(
            status(authorize(
                &with(vec![
                    h("Origin", "http://192.168.1.5:3210"),
                    h("Host", "192.168.1.5:3210")
                ]),
                T
            )),
            0
        );
        assert_eq!(
            status(authorize(
                &with(vec![
                    h("Origin", "HTTP://MyBox.local:3210"),
                    h("Host", "mybox.local:3210")
                ]),
                T
            )),
            0
        );
        assert_eq!(
            status(authorize(
                &with(vec![h("Origin", "null"), h("Host", "x:1")]),
                T
            )),
            403
        );
        assert_eq!(
            status(authorize(&with(vec![h("Origin", "http://x:1")]), T)),
            403
        );
    }

    #[test]
    fn authorize_checks_token_first() {
        let headers = [
            h("Content-Type", "text/plain"),
            h("Origin", "http://evil.example"),
            h("Host", "192.168.1.5:3210"),
        ];
        assert_eq!(status(authorize(&headers, T)), 401);
    }

    struct PanicReader;
    impl Read for PanicReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("body must not be read");
        }
    }

    #[test]
    fn body_limit_enforced() {
        assert_eq!(
            read_body_limited(PanicReader, Some(MAX_BODY_BYTES + 1), MAX_BODY_BYTES)
                .unwrap_err()
                .0,
            413
        );
        let big = std::io::repeat(b'a').take(MAX_BODY_BYTES as u64 + 1);
        assert_eq!(
            read_body_limited(big, None, MAX_BODY_BYTES).unwrap_err().0,
            413
        );
        let exact = std::io::repeat(b'a').take(MAX_BODY_BYTES as u64);
        assert_eq!(
            read_body_limited(exact, None, MAX_BODY_BYTES)
                .unwrap()
                .len(),
            MAX_BODY_BYTES
        );
    }

    #[test]
    fn json_body_parsing() {
        assert_eq!(
            parse_json_body(b"{not json").unwrap_err(),
            (400, "invalid JSON")
        );
        assert_eq!(parse_json_body(b"  ").unwrap(), json!({}));
        assert_eq!(parse_json_body(br#"{"a":1}"#).unwrap(), json!({"a": 1}));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn removed_and_unknown_commands_are_404() {
        for cmd in [
            "export_accounts_slim_text",
            "add_account_from_file",
            "nonexistent",
        ] {
            let (status, msg) = invoke_web_command(cmd, json!({})).await.unwrap_err();
            assert_eq!(status, 404, "{cmd}");
            assert!(msg.contains("Unsupported web command"), "{msg}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_export_passphrase_is_400() {
        let _home = TestHome::new();
        let (status, msg) = invoke_web_command(
            "export_accounts_full_encrypted_bytes",
            json!({"passphrase": "short"}),
        )
        .await
        .unwrap_err();
        assert_eq!(status, 400);
        assert!(msg.contains("at least 12"), "{msg}");
    }

    #[test]
    fn static_headers_present() {
        let headers = static_security_headers();
        let get = |name: &'static str| {
            headers
                .iter()
                .find(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default()
        };
        assert!(get("Content-Security-Policy").contains("frame-ancestors 'none'"));
        assert_eq!(get("X-Content-Type-Options"), "nosniff");
        assert_eq!(get("Referrer-Policy"), "no-referrer");
        assert_eq!(get("X-Frame-Options"), "DENY");
    }

    #[test]
    fn token_resolution() {
        let generated = resolve_web_token(None).unwrap();
        assert_eq!(generated.len(), 43);
        assert!(generated
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(resolve_web_token(Some("a".repeat(40))).is_err());
        assert!(resolve_web_token(Some("abcdefgh".repeat(4)[..31].to_string())).is_err());
        let err = resolve_web_token(Some("abcdefgh".repeat(5)[..31].to_string())).unwrap_err();
        assert!(err
            .to_string()
            .contains("at least 32 characters with at least 8 distinct characters"));
        assert!(resolve_web_token(Some("abcdefghij".repeat(4))).is_ok());
    }

    #[test]
    fn token_length_and_diversity_boundaries() {
        // 31 chars, 8 distinct: too short.
        let short = format!("{}{}", "abcdefgh".repeat(3), "abcdefg");
        assert_eq!(short.chars().count(), 31);
        assert!(resolve_web_token(Some(short)).is_err());
        // 32 chars, exactly 8 distinct: accepted.
        let exact = "abcdefgh".repeat(4);
        assert_eq!(exact.chars().count(), 32);
        assert!(resolve_web_token(Some(exact)).is_ok());
        // 32 chars, 7 distinct: rejected.
        let low = format!("{}{}", "abcdefg".repeat(4), "abcd");
        assert_eq!(low.chars().count(), 32);
        assert_eq!(low.chars().collect::<HashSet<_>>().len(), 7);
        assert!(resolve_web_token(Some(low)).is_err());
    }

    fn start_test_server() -> (Arc<Server>, std::net::SocketAddr) {
        start_test_server_on(Server::http("127.0.0.1:0").unwrap())
    }

    /// Runs the production handler pool on `server` with the test token.
    fn start_test_server_on(server: Server) -> (Arc<Server>, std::net::SocketAddr) {
        let server = Arc::new(server);
        let addr = server.server_addr().to_ip().unwrap();
        spawn_request_handlers(
            server.clone(),
            Arc::new(Runtime::new().unwrap()),
            Arc::new(std::env::temp_dir()),
            Arc::from(T),
            HANDLER_THREADS,
        );
        (server, addr)
    }

    fn stop(server: &Server) {
        for _ in 0..HANDLER_THREADS {
            server.unblock();
        }
    }

    fn connect(addr: std::net::SocketAddr) -> std::net::TcpStream {
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
    }

    /// Reads one chunk and returns its first line (the status line of a response).
    fn read_status_line(stream: &mut std::net::TcpStream) -> String {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// Reads until the peer closes (`true`) or the read times out (`false`).
    fn read_until_close(stream: &mut std::net::TcpStream) -> (String, bool) {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let closed = loop {
            match stream.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break true,
                Err(_) => break false,
            }
        };
        (String::from_utf8_lossy(&out).to_string(), closed)
    }

    fn raw_status(addr: std::net::SocketAddr, request: &str) -> String {
        use std::io::Write;
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn huge_content_length_does_not_crash_server() {
        let (server, addr) = start_test_server();
        for declared in ["18446744073709551615", "9223372036854775807"] {
            let first = raw_status(
                addr,
                &format!(
                    "POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\n\r\n"
                ),
            );
            assert!(first.contains("401"), "{first}");
            let second = raw_status(addr, "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(second.contains("200"), "{second}");
        }
        stop(&server);
    }

    #[test]
    fn error_responses_carry_security_headers() {
        use std::io::Write;
        let (server, addr) = start_test_server();
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(b"PUT /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        stream.read_to_string(&mut text).unwrap();
        let lower = text.to_ascii_lowercase();
        assert!(lower.starts_with("http/1.1 405"), "{text}");
        assert!(lower.contains("content-security-policy:"), "{text}");
        assert!(lower.contains("x-frame-options: deny"), "{text}");
        stop(&server);
    }

    #[test]
    fn idle_declared_body_does_not_stall_other_clients() {
        use std::io::Write;
        let (server, addr) = start_test_server();
        // More idle attackers than handler threads: each declares an in-budget body,
        // sends none and keeps the socket open.
        let mut idle = Vec::new();
        for _ in 0..HANDLER_THREADS + 1 {
            let mut stream = connect(addr);
            stream
                .write_all(b"POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2000000\r\n\r\n")
                .unwrap();
            let status = read_status_line(&mut stream);
            assert!(status.contains("401"), "{status}");
            idle.push(stream);
        }
        let started = std::time::Instant::now();
        let health = raw_status(addr, "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(health.contains("200"), "{health}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "health took {:?}",
            started.elapsed()
        );
        drop(idle);
        stop(&server);
    }

    #[test]
    fn oversized_declared_body_closes_connection_instead_of_parsing_it() {
        use std::io::Write;
        let (server, addr) = start_test_server();
        // Above the drain budget the body is skipped; the bytes that follow must not be
        // parsed as a second request on the same connection.
        let mut stream = connect(addr);
        stream
            .write_all(b"POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 20000000\r\n\r\nGET /api/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let (text, closed) = read_until_close(&mut stream);
        assert!(text.starts_with("HTTP/1.1 401"), "{text}");
        assert!(
            !text.contains("HTTP/1.1 200"),
            "smuggled request answered: {text}"
        );
        assert!(closed, "connection left open after skipped body");
        let health = raw_status(addr, "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(health.contains("200"), "{health}");
        stop(&server);
    }

    #[test]
    fn partial_body_then_reuse_closes_connection() {
        use std::io::Write;
        // Short socket timeout so the stalled drain gives up quickly.
        let (server, addr) = start_test_server_on(
            Server::http_with_timeout("127.0.0.1:0", std::time::Duration::from_millis(500))
                .unwrap(),
        );
        let mut stream = connect(addr);
        stream
            .write_all(b"POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2000\r\n\r\n0123456789")
            .unwrap();
        let status = read_status_line(&mut stream);
        assert!(status.contains("401"), "{status}");
        // Try to reuse the connection while the declared body is still incomplete.
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let (rest, closed) = read_until_close(&mut stream);
        assert!(
            !rest.contains("HTTP/1.1"),
            "answered on a desynced connection: {rest}"
        );
        assert!(closed, "connection left open after incomplete body");
        let health = raw_status(addr, "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(health.contains("200"), "{health}");
        stop(&server);
    }

    #[test]
    fn complete_body_keeps_connection_usable() {
        use std::io::Write;
        // Control for the poisoning tests: a fully sent body leaves keep-alive intact.
        let (server, addr) = start_test_server();
        let mut stream = connect(addr);
        let body = "x".repeat(2000);
        stream
            .write_all(
                format!(
                    "POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2000\r\n\r\n{body}"
                )
                .as_bytes(),
            )
            .unwrap();
        let status = read_status_line(&mut stream);
        assert!(status.contains("401"), "{status}");
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let (rest, _) = read_until_close(&mut stream);
        assert!(rest.contains("HTTP/1.1 200"), "{rest}");
        stop(&server);
    }

    #[test]
    fn socket_gate_rejects_missing_token_and_wrong_content_type() {
        let (server, addr) = start_test_server();
        let no_token = raw_status(
            addr,
            "POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert!(no_token.contains("401"), "{no_token}");
        let text_plain = raw_status(
            addr,
            &format!(
                "POST /api/invoke/list_accounts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {T}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"
            ),
        );
        assert!(text_plain.contains("415"), "{text_plain}");
        stop(&server);
    }

    #[test]
    fn invalid_static_path_is_404_with_security_headers() {
        use std::io::Write;
        let (server, addr) = start_test_server();
        let mut stream = connect(addr);
        stream
            .write_all(b"GET /a/../b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let (text, _) = read_until_close(&mut stream);
        let lower = text.to_ascii_lowercase();
        assert!(lower.starts_with("http/1.1 404"), "{text}");
        assert!(lower.contains("content-security-policy:"), "{text}");
        assert!(lower.contains("x-content-type-options: nosniff"), "{text}");
        stop(&server);
    }

    #[test]
    fn env_token_charset_is_restricted_and_not_echoed() {
        let base = "abcdefghijABCDEFGHIJ0123456789";
        for bad in ["+", "&", "#", "%", " ", "\n", "/", "=", "é"] {
            let value = format!("{base}{bad}xyz");
            let err = resolve_web_token(Some(value.clone()))
                .unwrap_err()
                .to_string();
            assert!(err.contains("may only contain"), "{bad:?}: {err}");
            assert!(!err.contains(base), "error echoes the token: {err}");
        }
        assert!(resolve_web_token(Some(format!("{base}.-_~"))).is_ok());
    }

    #[test]
    fn startup_url_host_formatting() {
        assert_eq!(display_host("0.0.0.0"), ("localhost".to_string(), true));
        assert_eq!(display_host("::"), ("localhost".to_string(), true));
        assert_eq!(display_host("::1"), ("[::1]".to_string(), false));
        assert_eq!(display_host("fd7a::5"), ("[fd7a::5]".to_string(), false));
        assert_eq!(display_host("127.0.0.1"), ("127.0.0.1".to_string(), false));
        assert_eq!(
            display_host("mybox.local"),
            ("mybox.local".to_string(), false)
        );
        assert_eq!(bind_address("::", 3210), "[::]:3210");
        assert_eq!(bind_address("[::1]", 3210), "[::1]:3210");
        assert_eq!(bind_address("0.0.0.0", 3210), "0.0.0.0:3210");
    }
}
