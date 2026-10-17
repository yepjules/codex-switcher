# Security Hardening — Design Spec

- Date: 2026-10-17
- Branch: `security-hardening` (worktree), base `origin/main` @ c357686
- Source: verified audit `codex-review-pipeline-v6-parallel/docs/security/2026-10-16-security-audit.md` (findings referenced as A#)
- Process note: the user directed autonomous execution. An aim review and up to 5 spec↔plan gap reviews replace the interactive approval gates of superpowers:brainstorming.
- Revision: aim-review fixes applied (A1 Origin edge cases and static headers, body handling, A3 dir migration, Windows retry and symlinks, A9 full call-site list, A10 edge case, A17 exit-code handling, CI notes).

## 1. Goal

Close every audit finding in codex-switcher that can be fixed without a product-owner decision, keeping existing features working:

- LAN web mode stays reachable on `0.0.0.0` (intentional) but requires a secret.
- Exported backups are protected by a secret only the user knows.
- Token files can't be corrupted, raced, or briefly world-readable.
- The desktop webview and release pipeline get defense in depth.

**Success criteria (testable):**

| ID | Criterion |
|----|-----------|
| SC1 | `POST /api/invoke/*` without a valid bearer token returns 401 and executes nothing. |
| SC2 | Cross-site requests (`text/plain` POST; DNS-rebinding page) cannot execute any command: a missing/incorrect token returns 401, a non-JSON body returns 415, and a foreign/`null` `Origin` returns 403. |
| SC3 | The web API no longer exposes `export_accounts_slim_text` or `add_account_from_file`. |
| SC4 | New full backups (v2) can't be decrypted without the user's passphrase. Legacy v1 backups still import. |
| SC5 | `accounts.json`, `settings.json`, `~/.codex/auth.json` and backup exports are written via temp-file + fsync + rename, created 0600 on Unix. The config dir is 0700, including existing installs. |
| SC6 | Concurrent store mutations in one process can't lose each other's writes. |
| SC7 | A stray callback (bad/missing `state`) no longer aborts an in-flight OAuth login. |
| SC8 | Every outbound HTTP request has connect and overall timeouts. Web request bodies are capped, and every request gets a response. |
| SC9 | The Tauri production CSP is strict; web-mode static pages carry an equivalent CSP and security headers; the app still renders and works. |
| SC10 | The release workflow has no `${{ }}` interpolation of user-controllable values in `run:`. Actions are SHA-pinned (with Dependabot), pnpm build-script policy is honored, and the heredoc delimiter is unguessable. |
| SC11 | The Windows shortcut launch no longer goes through `cmd.exe`, and still opens exactly one shortcut. |

## 2. Non-goals / out of scope

- **A16 updater endpoint** (points at upstream `Lampese`). Changing it needs the owner's own signing key and release channel. Documented in the PR as a follow-up decision.
- TLS for the LAN server. The bearer token travels in cleartext on plain HTTP; the README will recommend Tailscale (`tailscale serve`) or an SSH tunnel.
- Cross-process locking between `codex-web` and the desktop app running at the same time. SC6 is in-process only; documented.
- GitHub repo settings (protected environments, required reviewers). Documented, not code.
- The pipeline-skill findings (A7, A8, A12–A14). Those live outside this repository.
- A paste-token login prompt for web mode (the URL fragment is the only token entry path); the history caveat is documented instead.

## 3. Design

### 3.1 Web API authentication (A1, A11-body) — `src-tauri/src/web.rs`, `src/bin/codex-web.rs`, `src/lib/platform.ts`

**Token**
- On startup, `codex-web` generates 32 random bytes (OS RNG) and encodes them base64url without padding.
- Override: `CODEX_SWITCHER_WEB_TOKEN`, so bookmarks can stay stable. It must be ≥32 chars and contain ≥8 distinct characters; the server refuses to start otherwise.
- Startup prints `Open: http://<host>:<port>/#token=<token>`. When the host is `0.0.0.0`, it also prints a reminder to use the machine's LAN or tailnet address. The token is printed only to stdout and never logged elsewhere.

**Request gate for `/api/invoke/*`**, evaluated in this order before any body read:
1. `Authorization: Bearer <token>` must be present and match. Compare in constant time (`subtle::ConstantTimeEq`; already in the lockfile, added as a direct dependency). Otherwise **401** `{"error":"unauthorized"}`.
   **The token is the control that defeats CSRF and DNS rebinding.** A rebinding page's Origin equals its Host, so step 2 does not stop it. Never remove step 1 on the assumption that step 2 covers it.
2. Origin check (defense in depth). If `Origin` is present:
   - `Origin: null` → **403**;
   - `Host` missing → **403**;
   - otherwise Origin's authority (`host[:port]`) must equal `Host`, compared ASCII-case-insensitively, else **403**.
   No `Origin` → pass (non-browser clients).
3. `Content-Type` must start with `application/json`. Otherwise **415**. This forces a CORS preflight; the server sends no CORS headers, so browsers block cross-origin calls.
4. Body size, with `MAX_BODY_BYTES = 12 MiB` (leaves room for a base64-encoded 8 MiB backup):
   - `Content-Length` > `MAX_BODY_BYTES` → **413** without reading;
   - otherwise read through `.take(MAX_BODY_BYTES + 1)` (covers chunked bodies); exceeding → **413**.
5. Body that isn't valid JSON → **400** `{"error":"invalid JSON"}`. Today a parse error drops the request with no response; every request must now get one.

Steps 1–3 are a pure function `authorize(headers, token) -> Result<(), (u16, &'static str)>`, so they can be unit-tested without sockets.

**Left open:** `GET /api/health` and static files from `dist/` stay unauthenticated. They contain no secrets.

**Static responses** (`serve_file`): a bearer token lives in `sessionStorage` in web mode, so every static response carries:
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`

JSON API responses carry `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.

**Removed from the web surface:** `export_accounts_slim_text` (plaintext refresh tokens over HTTP) and `add_account_from_file` (reads arbitrary server paths). Both return **404** `Unsupported web command`.
- The browser UI doesn't call `add_account_from_file`; it uploads text via `add_account_from_auth_json_text` (verified: `useAccounts.ts:322` calls it only for Tauri string paths).
- The web UI *does* call slim export (`useAccounts.ts:364`, from `App.tsx`). Outside Tauri, the slim-export action must not call the backend. It shows "Slim export is unavailable in web mode; use the encrypted full backup" instead.

**Frontend (`platform.ts`)**
- On load, outside Tauri: if `location.hash` contains `token=`, store it in `sessionStorage["codexSwitcherWebToken"]`, then strip it with `history.replaceState`.
- `invokeBackend` sends `Authorization: Bearer <token>`.
- On 401, throw `Error("Web access token missing or invalid — reopen the URL printed by codex-web")`.
- Token parsing is a pure exported helper `extractTokenFromHash(hash: string): string | null`, so it's testable with node:test.

**Bind:** `0.0.0.0` stays the default (intentional).

### 3.2 Passphrase-protected backups (A2) — `src-tauri/src/commands/account.rs`, `src-tauri/src/web.rs`, `src/lib/platform.ts`, `src/App.tsx`, new `src/components/BackupPassphraseModal.tsx`

**Format v2**

```
"CSWF" | 0x02 | iterations: u32 BE | salt[16] | nonce[24] | ciphertext
```

- KDF: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023). No new crypto dependency.
- The full 49-byte v2 header (magic through nonce: 4+1+4+16+24) is passed as AEAD associated data, so a tampered iteration count fails decryption.
- Length checks are per version: a v2 file must be longer than 49 bytes and a v1 file longer than 45 bytes before any field is sliced, else "Encrypted file is invalid or truncated". Truncated input must never panic.
- Iterations read from a file must be within 100,000–2,000,000, otherwise the file is rejected as "Encrypted file header is invalid". This stops a crafted file from causing a CPU DoS on the single-threaded web server.

**Passphrase:** minimum 12 characters (Unicode scalar count), enforced in the backend (authoritative) and the UI. The UI counts with `[...passphrase].length`, not `.length`.

**Export API**
- `export_accounts_full_encrypted_file(path, passphrase)`
- `export_accounts_full_encrypted_bytes(passphrase)` (web: `{passphrase}` JSON)

Both always write v2.

**Import API**
- `import_accounts_full_encrypted_file(path, passphrase: Option<String>)`
- `import_accounts_full_encrypted_bytes(bytes, passphrase: Option<String>)` (web: `{contentsBase64, passphrase?}`)

Dispatch on the version byte:
- **v1:** decrypt with the legacy constant (renamed `LEGACY_V1_PASSPHRASE`, commented "read-only compatibility; never used for new exports"). The passphrase argument is ignored.
- **v2:** a missing or empty passphrase gives `"This backup is passphrase-protected"`. A wrong passphrase gives the existing "wrong passphrase or corrupted file" error.
- Other versions: the existing "Unsupported encrypted file version" error.

There's no downgrade path: v1 is decrypt-only, and a v2 file can't be rewritten as v1 without its key.

**UI:** `BackupPassphraseModal`
- Export mode: passphrase + confirm, ≥12 chars, must match.
- Import mode: a single field with the hint "Leave blank for backups made before this version".
- Inputs are `type="password"` with `autocomplete="new-password"` / `"current-password"`.
- The passphrase stays in component state only. It is never persisted or logged, and is cleared on close.
- The modal follows the existing modal pattern (`SettingsModal.tsx`).
- `exportFullBackupFile(passphrase)` and `importFullBackupFile(passphrase?)` take the value from the modal.
- In Tauri, the passphrase is collected first and the file dialog opens second.

### 3.3 Secure atomic file writes (A3) — new `src-tauri/src/auth/secure_fs.rs`

`pub fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()>`:
1. **Symlinks:** if `path` is a symlink (e.g. a dotfile-managed `~/.codex/auth.json`), resolve it with `fs::canonicalize` and use the resolved target as the path. The temp file goes in the target's directory, so the link is preserved. A code comment documents this choice.
2. Ensure the parent exists. Directories this creates get mode 0700 on Unix.
3. Create the temp file `<parent>/.<filename>.tmp-<pid>-<16 hex random>` with `OpenOptions::new().write(true).create_new(true)` plus `.mode(0o600)` on Unix. `create_new` refuses to follow a pre-planted temp-file symlink.
4. `write_all`, then `sync_all`.
5. `fs::rename(tmp, path)`. This replaces atomically on Unix and uses `MoveFileExW(REPLACE_EXISTING)` on Windows.
   **Windows only:** on `PermissionDenied` or raw OS error 32 (sharing violation), retry up to 5 times with 50 ms sleeps, then fail. This covers Codex or antivirus holding `auth.json` open without `FILE_SHARE_DELETE`.
6. Unix: best-effort `fsync` of the parent directory.

On any error, remove the temp file and return the error. The original file is left intact.

`pub fn ensure_private_dir(path: &Path) -> anyhow::Result<()>`:
- Creates the directory if missing, and on Unix sets 0700 **even if the directory already exists**. This migrates existing 0755 installs.
- Called inside `save_accounts` and `save_app_settings`, for `~/.codex-switcher` only. It must never chmod `~/.codex`, which Codex CLI owns.

**Call sites to convert** (all current `fs::write` of secrets/settings):
- `storage.rs` `save_accounts`, `save_app_settings`
- `switcher.rs` `switch_to_account` (auth.json)
- `account.rs` `write_encrypted_file`

A post-write `set_permissions` is no longer needed.

**Acceptance:** `grep -rn 'fs::write' src-tauri/src` finds no secret or settings writes outside `secure_fs.rs` (test code excepted).

### 3.4 In-process store mutation lock (A9) — `src-tauri/src/auth/storage.rs` (+ callers)

- Add `static STORE_LOCK: std::sync::Mutex<()>`.
- Add `pub fn mutate_accounts<R>(f: impl FnOnce(&mut AccountsStore) -> anyhow::Result<R>) -> anyhow::Result<R>`, which holds the lock across `load_accounts` → `f` → save. If `f` returns `Err`, nothing is saved.
- A poisoned lock is recovered with `into_inner` (the store on disk is still the source of truth).

**Rules**
- Every function that does load→modify→save **anywhere in `src-tauri/src`** goes through `mutate_accounts`. The known list, verified 2026-10-17 via `grep -rn save_accounts`:
  - `storage.rs`: `add_account`, `remove_account`, `set_active_account`, `touch_account`, `update_account_metadata`, `update_account_chatgpt_tokens`, `set_masked_account_ids`;
  - `auth/token_refresh.rs`: `load_account_reconciling_live_auth` (the save at :166);
  - `commands/account.rs`: the switch path (the save at :161 after `sync_active_account_tokens`) and the three import merges (:243, :279, :293).
- Closures must not call other `mutate_accounts` users (no re-entrancy) and must not `.await`.
- Imports do their network or async work first, then call `mutate_accounts(|current| merge(current, imported))`, so the merge sees a fresh store.
- `save_accounts` becomes private to `storage.rs`. Tests that seed a store use a `#[cfg(test)] pub(crate)` helper or `mutate_accounts`.
- **Acceptance:** outside test code, `grep -rn 'save_accounts(' src-tauri/src` matches only the definition and the call inside `mutate_accounts`.
- **Lock ordering:** `AUTH_OPERATION_LOCK` (async) may be held while taking `STORE_LOCK`, never the reverse. `STORE_LOCK` is never held across `.await`.

### 3.5 OAuth callback robustness (A10) — `src-tauri/src/auth/oauth_server.rs`

In the callback handler:
- If `state` is missing or ≠ expected, respond 400 with the constant body `"State mismatch"` (never echoing request parameters) and **continue** waiting. Do not return `HandleResult::Error`. This applies whether or not `error` is present.
- Only when `state` matches:
  - `error` present → terminate with error, as today;
  - else `code` present → exchange;
  - else (neither) → terminate with "Missing authorization code" (current behavior).
- Extract this as a pure function `classify_callback(params, expected_state) -> CallbackAction { Ignore(&'static str) | Fail(String) | Exchange(String) }` and unit-test it (alongside the existing `commands/oauth_tests.rs` patterns).

CSRF and code-injection protection are unchanged, because state is still verified before both the error and code branches.

### 3.6 HTTP timeouts (A11) — new `src-tauri/src/api/http.rs`

- `pub fn http_client() -> &'static reqwest::Client`, built once (`OnceLock`) with `connect_timeout(10s)` and `timeout(30s)`.
- Replace all `reqwest::Client::new()` calls: `oauth_server.rs:96`, `api/usage.rs:229,366,382`, `commands/account_stats.rs:222,262`, `auth/token_refresh.rs:290`.
- Where a request already sets a per-request `.timeout(..)` (token refresh), keep it; the per-request value overrides the client default.
- **Acceptance:** `grep -rn 'Client::new()' src-tauri/src` returns nothing.

### 3.7 Webview CSP (A6) — `src-tauri/tauri.conf.json`

```
"csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: asset: http://asset.localhost; font-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
```

- `"devCsp": null`, so Vite HMR keeps working.
- `"freezePrototype": true`.

Verification: `pnpm build` succeeds and the bundled `dist/index.html` and `tray.html` contain no inline `<script>` blocks. A grep of `src/` showed no external fetch or images (verified 2026-10-17).

### 3.8 CI / release hardening (A4, A5, A15) — `.github/workflows/*.yml`, `.github/dependabot.yml`, `package.json`

**`build.yml`**
- Top-level `permissions: {}`. The release job gets `contents: write` only.
- "Determine tag": pass `INPUT_VERSION: ${{ inputs.version }}`, `REF_NAME: ${{ github.ref_name }}` and `EVENT_NAME: ${{ github.event_name }}` via `env:`. Validate the chosen tag against `^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$` and fail otherwise.
- Release note: use the delimiter `EOF_$(openssl rand -hex 16)`. Use `"$EVENT_NAME"` instead of `${{ github.event_name }}` in `run:`.
- `actions/checkout` with `persist-credentials: false`. tauri-action uses `GITHUB_TOKEN` from env, not git credentials.
  - The release-note step's `git fetch origin refs/tags/…` works unauthenticated because `yepjules/codex-switcher` is public (verified 2026-10-17 via `gh repo view`).
  - Add a workflow comment noting that a private fork would need an auth header for that step.
- Pin every `uses:` in all workflows to a full 40-char commit SHA with a `# vX.Y.Z` comment.
  - SHAs are resolved with `gh api repos/<owner>/<repo>/commits/<tag>` (returns the commit SHA, dereferencing annotated tags) at implementation time.
  - `dtolnay/rust-toolchain` is pinned to the SHA of its `stable` branch head, with comment `# stable`.
- Add `.github/dependabot.yml` with `package-ecosystem: github-actions` (weekly), so SHA pins get updates.

**pnpm**
- Add `"packageManager": "pnpm@<version that honors allowBuilds>"` to `package.json` and remove `version: 9` from `pnpm/action-setup` everywhere, so CI honors `pnpm-workspace.yaml` `allowBuilds`.
- The exact version must be one the lockfile format accepts. The implementer verifies by running `pnpm install --frozen-lockfile` locally with that version.
- All CI installs use `pnpm install --frozen-lockfile`.

### 3.9 Windows shortcut launch (A17) — `src-tauri/src/commands/process.rs`

- `open_windows_shortcut` runs `Command::new(<%SystemRoot%>\explorer.exe).arg(path)`. The absolute path comes from the `SystemRoot` env var, with fallback `C:\Windows`; there is no PATH lookup and no `cmd.exe`.
- It keeps `CREATE_NO_WINDOW` and returns `spawn().is_ok()`.
- It must **not** use `command_succeeds`. That function checks the exit status, and explorer commonly exits 1 on success, which would make the caller loop (`process.rs:~1183`) launch every candidate shortcut. A code comment explains this.

### 3.10 Docs — `README.md`

Update the LAN section:
- the token URL, and that the token is a secret. The `#token=` URL may be recorded in browser history or sync before it is stripped; prefer a private window or clear that history entry;
- `CODEX_SWITCHER_WEB_TOKEN`;
- the HTTP-cleartext caveat, with a Tailscale/SSH recommendation;
- slim export is unavailable in web mode.

Backups section:
- a passphrase is now required;
- old `.cswf` files still import, but they are protected only by a key that is public in the source. Re-export with a passphrase and delete the old files.

## 4. Error handling summary

| Case | Response |
|------|----------|
| No/bad token | 401 JSON |
| Foreign Origin, `Origin: null`, or Origin without Host | 403 |
| Wrong content type | 415 |
| Oversized body (Content-Length or streamed) | 413 |
| Invalid JSON body (authorized) | 400 JSON |
| Removed command | 404 JSON |
| v2 backup, no passphrase | user-visible "This backup is passphrase-protected" |
| Short passphrase | user-visible "Passphrase must be at least 12 characters" (backend and UI) |
| Iteration count out of range | "Encrypted file header is invalid" |
| Atomic write failure | temp file removed, original intact, error propagated |
| Windows rename blocked by open handle | up to 5 retries × 50 ms, then error (original intact) |
| Stray OAuth callback | 400 "State mismatch" to the requester, login continues |
| Weak `CODEX_SWITCHER_WEB_TOKEN` | server refuses to start with a clear message |

## 5. Testing

**Rust unit tests** (`cargo test`):
- `web::authorize`: missing token, wrong token, right token; foreign Origin; matching Origin (case-insensitive); `Origin: null`; Origin without Host; no Origin; wrong content type.
- Body handling: Content-Length over the cap → 413; streamed body over the cap → 413; invalid JSON → 400.
- Removed commands → error.
- Static response headers include CSP, nosniff, no-referrer and DENY.
- Env token validation: under 32 chars rejected; low diversity rejected; a valid token accepted.
- Backups: v2 round-trip; v2 wrong passphrase; v2 empty passphrase; short passphrase rejected on export; v1 legacy file (encoded with the legacy constant in-test) still imports; out-of-range iterations rejected; header tamper (iteration byte flipped, value still in range) fails; decrypting with empty AAD fails while decrypting with the 49-byte header succeeds (proves AAD binding).
- `secure_fs` (unix-gated where noted):
  - file mode 0600; new dir 0700; an existing 0755 dir is tightened to 0700;
  - an existing file is replaced, and no temp file is left on success;
  - writing through a symlink updates the target and keeps the link.
- `mutate_accounts`: N threads each append a distinct account; all N are present afterwards (uses the `test_support` temp config dir); a closure returning `Err` leaves the file unchanged.
- `classify_callback`: every branch, including state-ok with neither code nor error.

**TS** (`node --experimental-strip-types --test`):
- `tests/webToken.test.ts` for `extractTokenFromHash`: present, absent, among other params, URL-encoded.
- Add a `test:web-token` script.

**Build gates:**
- `cargo test`;
- `cargo clippy --all-targets -- -D warnings` if the base is clean (otherwise no new warnings);
- `pnpm exec tsc --noEmit`, `pnpm build`, and all existing node tests.

**Manual smoke** (run during implementation; results go in the PR): start `codex-web`, then
- `curl` without a token → 401;
- `curl` with the token → `list_accounts` 200;
- `text/plain` POST with the token → 415;
- `export_accounts_slim_text` with the token → 404;
- `GET /` → CSP header present.

## 6. Risks

1. **CSP breaks rendering** in a production bundle in ways tsc/build can't catch. Mitigation: devCsp null; build and inspect; PR notes a manual check.
2. **pnpm version bump** could change lockfile semantics. Mitigation: `--frozen-lockfile` must pass unchanged; if no compatible version honors `allowBuilds`, fall back to `onlyBuiltDependencies: [esbuild]` in `package.json`, which pnpm 9 honors.
3. **Re-entrancy deadlock** in `mutate_accounts`. Mitigation: the code-review rule, plus a test exercising every converted function once.
4. **Existing v1 backups remain weak.** Mitigation: the README tells users to re-export and delete them; v1 stays decrypt-only.
