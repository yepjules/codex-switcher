use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

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
    .filter_map(|(name, value)| header(name, value).ok())
    .collect()
}

pub fn run_lan_server(host: &str, port: u16, token: String) -> anyhow::Result<()> {
    if let Err(err) = crate::auth::harden_config_permissions() {
        eprintln!("[Startup] Failed to harden config permissions: {err:#}");
    }
    let address = format!("{host}:{port}");
    let server = Server::http(&address)
        .map_err(|err| anyhow::anyhow!("Failed to bind HTTP server on {address}: {err}"))?;
    let runtime = Runtime::new().context("Failed to start async runtime")?;
    let dist_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("dist");

    println!("Codex Switcher web server listening on http://{address}");
    println!("Serving static files from {}", dist_dir.display());
    let display_host = if host == "0.0.0.0" { "localhost" } else { host };
    println!("Open: http://{display_host}:{port}/#token={token}");
    if host == "0.0.0.0" {
        println!(
            "Listening on all interfaces — replace localhost with this machine's LAN or tailnet address"
        );
    }

    for request in server.incoming_requests() {
        if let Err(error) = handle_request(request, &runtime, &dist_dir, &token) {
            eprintln!("[web] request failed: {error:#}");
        }
    }

    Ok(())
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
        sanitize_path(url)?
    };
    let candidate = dist_dir.join(&requested);

    if candidate.is_file() {
        return serve_file(request, candidate);
    }

    if requested.extension().is_some() {
        respond_text(
            request,
            StatusCode(404),
            "Not Found",
            "text/plain; charset=utf-8",
        )?;
        return Ok(());
    }

    serve_file(request, dist_dir.join("index.html"))
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
    let data = fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
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
    let response = Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(header("Content-Type", content_type)?);
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
}
