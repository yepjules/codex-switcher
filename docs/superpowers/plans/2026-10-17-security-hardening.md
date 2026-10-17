# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close audit findings A1–A6, A9–A11, A15, A17 in codex-switcher per the spec, without breaking desktop or LAN-web features.

**Architecture:** Two new focused Rust modules (`auth/secure_fs.rs` for atomic private writes, `api/http.rs` for a shared timed HTTP client). One store-mutation choke point (`mutate_accounts`) in `auth/storage.rs`. A pure `authorize` gate plus a response-header layer in `web.rs`. A v2 backup format in `commands/account.rs`. Frontend changes are confined to `lib/platform.ts`, one new modal, and `App.tsx` wiring. CI changes are YAML-only plus `package.json`.

**Tech Stack:** Rust (Tauri 2, tiny_http, reqwest, tokio, chacha20poly1305, pbkdf2, subtle), React 19 + TypeScript, Vite, pnpm, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-17-security-hardening-design.md` (read it before every task; section refs below are §N).

**Execution roles:**
- **Coder** subagent: implements a task with TDD and commits.
- **Code-quality reviewer** subagent: reviews each task's diff for correctness, idiom and fit with surrounding code.
- **Auditor** subagent: reviews each task's diff against the spec's security intent (§1 success criteria).

A task is done only when both reviewers pass or their findings are fixed.

## Global Constraints

- Work only in the worktree `/Users/jules/codex-review-pipeline-v6-parallel/codex-switcher/.claude/worktrees/security-hardening` on branch `security-hardening`. Never push and never touch `main`. The coordinator pushes at the end.
- Commits: conventional prefixes (`feat:`, `fix:`, `ci:`, `docs:`, `test:`). **No `Co-Authored-By` or other attribution lines.**
- **No new crates** except `subtle` as a direct dependency (it is already in `Cargo.lock`). No new npm dependencies.
- Rust gates: `cd src-tauri && cargo test` passes, and `cargo clippy --all-targets` shows no new warnings versus base `c357686`.
- TS gates: `pnpm exec tsc --noEmit`, `pnpm build`, and every `tests/*.test.ts` via `node --experimental-strip-types --test <file>` pass.
- Never print, log or commit token, passphrase or refresh-token values. The legacy v1 constant stays in source but must not be copied into docs, tests output or commit messages.
- `MAX_BODY_BYTES = 12 * 1024 * 1024`
- KDF: 600_000 iterations; accepted range 100_000..=2_000_000
- Minimum passphrase: 12 chars
- HTTP client: connect 10 s, total 30 s
- Windows rename retry: 5 × 50 ms
- Env token: ≥32 chars, ≥8 distinct
- Unix modes: files 0600, `~/.codex-switcher` 0700; never chmod `~/.codex`.
- Tests that touch the filesystem use `auth::test_support::TestHome` (thread-local fake home).

## Review Focus

1. **The web UI after the change (token in sessionStorage):** opening the bare URL with no `#token=` must show the clear 401 message (§3.1), not a blank screen or a JSON parse error. Pinned in Task 7 Step 1 (the `invokeBackend` tests with stubbed `fetch`/`sessionStorage`: 401 maps to the exact message, and the Bearer header is sent).
2. **Existing installs with a 0755 `~/.codex-switcher` and a 0644 `accounts.json`:** after the first save, both must be tightened. Pinned in Task 1 (existing-dir test) and Task 2 (save-tightens test).
3. **Switching accounts while Codex holds `auth.json` open on Windows:** this must still succeed within the retry window. Windows can't be tested in CI here, so the retry function is unit-tested with an injected rename closure in Task 1.
4. **Importing an old (v1) backup with the passphrase field left blank:** must import with no extra prompt or error. Pinned in Task 5 (v1-legacy test with `None` and with `Some("")`).
5. **An idle OAuth login receiving a favicon or a stray request** (e.g. `/favicon.ico` or a callback without state): the login must keep waiting. Pinned in Task 4 (`classify_callback` missing-state test). The non-callback path is already `Continue`.

---

### Task 1: `secure_fs` — atomic private file writes (§3.3)

**Files:**
- Create: `src-tauri/src/auth/secure_fs.rs`
- Modify: `src-tauri/src/auth/mod.rs` (add `pub mod secure_fs;`)

**Interfaces:**
- Produces:
  - `pub fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()>`
  - `pub fn ensure_private_dir(path: &Path) -> anyhow::Result<()>`
  - `fn rename_with_retry(from: &Path, to: &Path, rename: impl FnMut(&Path, &Path) -> std::io::Result<()>, retries: u32, delay: Duration) -> std::io::Result<()>`. This is private.
    - Behavior: 1 initial attempt plus up to `retries` additional attempts, retrying only on `PermissionDenied` or raw OS error 32.
    - Callable on all platforms for testability. Windows passes `retries = 5` (§3.3: 5 retries × 50 ms); Unix passes 0.

- [ ] **Step 1: Write failing tests** in `secure_fs.rs` `#[cfg(test)] mod tests`, using `std::env::temp_dir()` + uuid subdirs (no TestHome needed):
  - `writes_file_with_0600_and_no_temp_left` (unix): assert content equals the input, `mode & 0o777 == 0o600`, and that no entry in the parent starts with `.<name>.tmp-`.
  - `replaces_existing_file_atomically`: write "a" then "b" and assert "b".
  - `creates_missing_parent_with_0700` (unix).
  - `ensure_private_dir_tightens_existing_0755` (unix): chmod an existing dir to 0755, call it, assert 0700.
  - `writes_through_symlink_and_preserves_link` (unix): create a target file and symlink `link → target`, `write_private_file(link, b"x")`, then assert `symlink_metadata(link).file_type().is_symlink()` and that the target content is `"x"`.
  - `rename_retry_recovers_after_sharing_violation`: a closure that fails twice with `io::Error::from_raw_os_error(32)` and then succeeds, with retries=5 and delay=0 → Ok, and the closure was called 3 times.
  - `rename_retry_gives_up_after_retries`: a closure that always returns `PermissionDenied`, with retries=5 → Err, called exactly 6 times.
  - `rename_retry_does_not_retry_other_errors`: `NotFound` → Err after 1 call.
- [ ] **Step 2: Run them and confirm they fail.** Run `cd src-tauri && cargo test secure_fs`. Expected: compile error / FAIL.
- [ ] **Step 3: Implement** per §3.3 steps 1–6.
  - The temp name is `.{file_name}.tmp-{pid}-{16 hex}`, with the hex from `rand::rng().fill_bytes`.
  - Use `std::os::unix::fs::{OpenOptionsExt, PermissionsExt}` behind `#[cfg(unix)]`.
  - The parent-dir fsync is best effort: ignore its errors.
  - On any failure after the temp file is created, `let _ = fs::remove_file(&tmp)`.
- [ ] **Step 4: Run the tests and confirm they pass.** `cargo test secure_fs` → all PASS.
- [ ] **Step 5: Commit.** `git commit -m "feat: add atomic private file writer"`

### Task 2: Route all secret writes and store mutations through safe paths (§3.3 call sites, §3.4)

**Files:**
- Modify: `src-tauri/src/auth/storage.rs`
- Modify: `src-tauri/src/auth/switcher.rs:38-60`
- Modify: `src-tauri/src/auth/token_refresh.rs:158-170`
- Modify: `src-tauri/src/commands/account.rs:150-165, 225-295, ~657` (`write_encrypted_file`)
- Modify: `src-tauri/src/auth/test_support.rs`
- Modify: `src-tauri/src/commands/oauth_tests.rs` (`save_accounts` → test seed helper)

**Interfaces:**
- Consumes: Task 1 `write_private_file`, `ensure_private_dir`.
- Produces:
  - `pub fn mutate_accounts<R>(f: impl FnOnce(&mut AccountsStore) -> anyhow::Result<R>) -> anyhow::Result<R>`
  - `#[cfg(test)] pub(crate) fn seed_accounts_for_test(store: &AccountsStore) -> anyhow::Result<()>`
  - `save_accounts` becomes private (`fn`).
  - `test_support::TestHome::share(&self) -> SharedTestHome` plus `SharedTestHome::install(&self) -> SharedGuard`. These install the same root in another thread; the guard clears the thread-local on drop without deleting anything.

- [ ] **Step 1: Write failing tests** in `storage.rs` `#[cfg(test)] mod tests`:
  - `concurrent_mutations_do_not_lose_writes`: create a `TestHome` and seed an empty store. Spawn 16 `std::thread`s; each does `home.share().install()`, then `add_account(<unique StoredAccount>)`. Join all and assert `load_accounts()?.accounts.len() == 16`.
  - `mutate_error_leaves_store_unchanged`: seed 1 account; `mutate_accounts(|s| { s.accounts.clear(); anyhow::bail!("x") })` is Err, and there is still 1 account on disk.
  - `mutate_without_change_skips_write` (unix): seed, record the mtime, sleep 10 ms, `mutate_accounts(|_| Ok(()))`, and assert the mtime is unchanged.
  - `save_tightens_existing_dir_and_file` (unix): pre-create `.codex-switcher` 0755 and `accounts.json` 0644, call `add_account`, then assert 0700 / 0600.
  - `every_converted_mutator_runs_without_deadlock` (spec §6 risk 3). Run the body on a spawned thread that installs `home.share()` and signals over an `mpsc` channel; the main thread does `recv_timeout(Duration::from_secs(10))` and panics with "deadlock" on timeout. Inside a seeded store (2 ChatGPT accounts, one active), call each once and assert it returns:
    - `add_account`, `set_active_account`, `touch_account`, `update_account_metadata`, `update_account_chatgpt_tokens`, `set_masked_account_ids`, `remove_account`;
    - `token_refresh::load_account_reconciling_live_auth`, with a seeded `~/.codex/auth.json`, made `pub(crate)` for the test if needed;
    - `mutate_accounts(|s| { let (m, _) = merge_accounts_store(std::mem::take(s), AccountsStore::default()); *s = m; Ok(()) })`, standing in for the switch-path and import merges (make `merge_accounts_store` `pub(crate)` if needed).
- [ ] **Step 2: Run them and confirm they fail.** `cargo test storage::tests` → FAIL (`mutate_accounts`/`share` undefined).
- [ ] **Step 3: Implement.**
  - `static STORE_LOCK: std::sync::Mutex<()> = Mutex::new(())`. Recover poison with `unwrap_or_else(|e| e.into_inner())`.
  - `mutate_accounts`: lock → `load_accounts` → `serde_json::to_vec(&store)` snapshot → `f(&mut store)` → if Err return Err → if `to_vec(&store) != snapshot` call `save_accounts` → return R.
  - `save_accounts` / `save_app_settings`: `ensure_private_dir(config_dir)` then `write_private_file(path, json)`. Delete the `set_permissions` blocks.
  - Rewrite `add_account`, `remove_account`, `set_active_account`, `touch_account`, `update_account_metadata`, `update_account_chatgpt_tokens` and `set_masked_account_ids` as `mutate_accounts(|store| { …existing body minus load/save… })`.
  - `token_refresh.rs::load_account_reconciling_live_auth`: `mutate_accounts(|store| { let is_active = …; if is_active { if let Some(auth) = read_current_auth()? { reconcile_active_account_from_auth(store, account_id, &auth); } } find account; Ok((account.clone(), is_active)) })`. `read_current_auth()` must stay inside the active branch, as today, so a malformed `auth.json` can't break refreshes for non-active accounts. It's sync file I/O with no `.await`, so it's allowed inside the closure.
  - `account.rs` switch path (:161): `mutate_accounts(|store| { sync_active_account_tokens(store, &auth); Ok(()) })`, then re-read the target account from the returned or reloaded store for the rest of the function.
  - `account.rs` imports (:243, :279, :293): after decode/validate (and the `await` for slim), do `let summary = mutate_accounts(|current| { let (merged, summary) = merge_accounts_store(std::mem::take(current), imported); *current = merged; Ok(summary) })`. The slim path builds `existing_names` from a `load_accounts()` snapshot before the network call; that's acceptable because merge re-checks duplicates. Leave a comment saying so.
  - `switcher.rs::switch_to_account`: `write_private_file(&auth_path, content.as_bytes())`, with no chmod block and no `ensure_private_dir` for `~/.codex`.
  - `account.rs::write_encrypted_file`: `write_private_file(Path::new(path), bytes)`.
  - `test_support`: add `share`/`install` as described above. Assert in `install` that the thread has no home yet.
  - `oauth_tests.rs`: replace `save_accounts(` with `seed_accounts_for_test(`.
- [ ] **Step 4: Run all tests and check acceptance.**
  - `cargo test` → all PASS (61 previously plus the new tests).
  - `grep -rn 'save_accounts(' src-tauri/src | grep -v 'fn save_accounts\|mutate_accounts\|seed_accounts_for_test'` → only the single call inside `mutate_accounts`/`seed_accounts_for_test`.
  - `grep -rn 'fs::write' src-tauri/src` → none outside tests.
- [ ] **Step 5: Commit.** `git commit -m "fix: serialize account store mutations and write secrets atomically"`

### Task 3: Shared HTTP client with timeouts (§3.6)

**Files:**
- Create: `src-tauri/src/api/http.rs`
- Modify: `src-tauri/src/api/mod.rs` (`pub mod http;`), `src-tauri/src/auth/oauth_server.rs:96`, `src-tauri/src/api/usage.rs:229,366,382`, `src-tauri/src/commands/account_stats.rs:222,262`, `src-tauri/src/auth/token_refresh.rs:290`

**Interfaces:**
- Produces: `pub fn http_client() -> &'static reqwest::Client` (a `OnceLock`). It panics only if the builder fails, which is impossible with these options; document that with `.expect("static reqwest config")`.

- [ ] **Step 1: Write the failing test** `http_client_is_singleton` in `http.rs`: `assert!(std::ptr::eq(http_client(), http_client()))`.
- [ ] **Step 2: Run it and confirm it fails.** `cargo test http_client` → FAIL.
- [ ] **Step 3: Implement** the builder with `.connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30))`. Replace each `reqwest::Client::new()` with `crate::api::http::http_client()` and adjust bindings to `&Client` (most call sites do `client.post(..)`, which works on `&Client`). Keep token refresh's per-request `.timeout(..)`.
- [ ] **Step 4: Run the tests and check acceptance.** `cargo test` PASS; `grep -rn 'Client::new()' src-tauri/src` → empty.
- [ ] **Step 5: Commit.** `git commit -m "fix: add connect and request timeouts to all HTTP calls"`

### Task 4: OAuth callback classification (§3.5)

**Files:**
- Modify: `src-tauri/src/auth/oauth_server.rs:255-330`
- Test: `src-tauri/src/auth/oauth_server.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `enum CallbackAction { Ignore(&'static str), Fail(String), Exchange(String) }` and `fn classify_callback(params: &HashMap<String, String>, expected_state: &str) -> CallbackAction`. Both are module-private.

- [ ] **Step 1: Write failing tests**, one per case:

  | Input | Expected |
  |---|---|
  | missing state, has `code` | `Ignore("State mismatch")` |
  | wrong state + `error=access_denied` | `Ignore("State mismatch")` |
  | missing state + `error` | `Ignore` |
  | right state + `error=x&error_description=y` | `Fail` containing "x" |
  | right state + `code=abc` | `Exchange("abc")` |
  | right state + empty `code` | `Fail("Missing authorization code")` |
  | right state, neither | `Fail("Missing authorization code")` |

- [ ] **Step 2: Run them and confirm they fail.** `cargo test classify_callback` → FAIL.
- [ ] **Step 3: Implement** `classify_callback`, then replace the inline error/state/code block in `handle_oauth_request` with a `match`:
  - `Ignore(body)` → respond 400 `body`, return `HandleResult::Continue`;
  - `Fail(msg)` → respond 400 with `"OAuth Error"` or `"Missing authorization code"` as today, return `HandleResult::Error`;
  - `Exchange(code)` → the existing exchange code.
  The state comparison stays a plain `==`; state isn't a long-lived secret and only needs to be unpredictable.
- [ ] **Step 4: Run the tests and confirm they pass.** `cargo test` PASS (including the existing `commands/oauth_tests.rs`).
- [ ] **Step 5: Commit.** `git commit -m "fix: ignore stray OAuth callbacks instead of aborting login"`

### Task 5: Backup format v2 with user passphrase — backend (§3.2)

**Files:**
- Modify: `src-tauri/src/commands/account.rs` (constants ~:39-44, export/import commands :251-295, `encode_full_encrypted_store`/`decode_full_encrypted_store`/`derive_encryption_key` ~:555-636)
- Test: same file, `#[cfg(test)] mod tests` (create one if absent)

**Interfaces:**
- Produces (Tauri commands; argument names are camelCased by Tauri to `passphrase`):
  - `export_accounts_full_encrypted_file(path: String, passphrase: String) -> Result<(), String>`
  - `export_accounts_full_encrypted_bytes(passphrase: String) -> Result<Vec<u8>, String>`
  - `import_accounts_full_encrypted_file(path: String, passphrase: Option<String>) -> Result<ImportAccountsSummary, String>`
  - `import_accounts_full_encrypted_bytes(bytes: Vec<u8>, passphrase: Option<String>) -> Result<ImportAccountsSummary, String>`
  - Internals: `fn encode_full_v2(store: &AccountsStore, passphrase: &str, iterations: u32) -> anyhow::Result<Vec<u8>>`, `fn decode_full(file_bytes: &[u8], passphrase: Option<&str>) -> anyhow::Result<AccountsStore>`, `fn validate_new_passphrase(p: &str) -> anyhow::Result<()>`.
- Constants:
  - `FULL_FILE_VERSION_V1: u8 = 1`, `FULL_FILE_VERSION_V2: u8 = 2`
  - `FULL_KDF_ITERATIONS_V1 = 210_000`, `FULL_KDF_ITERATIONS_V2 = 600_000`
  - `MIN_KDF_ITERATIONS = 100_000`, `MAX_KDF_ITERATIONS = 2_000_000`
  - `MIN_PASSPHRASE_CHARS = 12`
  - Rename `FULL_PRESET_PASSPHRASE` → `LEGACY_V1_PASSPHRASE` with the doc comment from §3.2.

- [ ] **Step 1: Write failing tests:**
  - `v2_round_trip`: encode a store with 1 account using `"correct horse battery"` (iterations 100_000 for test speed, via `encode_full_v2`), decode it with `Some` of the same passphrase, and assert the account names are equal.
  - `v2_wrong_passphrase_fails`: the error contains "wrong passphrase".
  - `v2_missing_passphrase_fails`: both `None` and `Some("")` give errors containing "passphrase-protected".
  - `short_passphrase_rejected`: `validate_new_passphrase("short")` errors with exactly "Passphrase must be at least 12 characters"; the 12-char `"abcdefghijkl"` is Ok; the 12-scalar string `"ééééééééééé1"` is Ok.
  - `v1_legacy_still_imports`: build a v1 blob with the old layout (magic | 1 | salt | nonce | ct, key = PBKDF2(LEGACY_V1_PASSPHRASE, 210_000), no AAD) using a test helper, then `decode_full(&blob, None)` and `decode_full(&blob, Some(""))` both Ok.
  - `v2_iterations_out_of_range_rejected`: hand-edit the header iterations to 50_000 and then to 5_000_000 → "header is invalid".
  - `v2_header_tamper_fails` (spec §5 "iteration byte flipped"): change the low byte of the iteration field so the value stays in range (e.g. 100_000 → 100_001) → decrypt error.
  - `v2_header_is_bound_as_aad`. Proves AAD binding independently of key derivation: encode a blob, derive the key from its salt and iterations with `derive_encryption_key`, then decrypt the ciphertext directly with `Payload { msg, aad: &[] }` → Err, and with `aad: &blob[..49]` → Ok.
  - `imports_run_under_store_lock_without_deadlock` (spec §6 risk 3, real import paths). Inside a `TestHome` seeded with 1 account, using a `#[tokio::test(flavor = "current_thread")]` wrapped in `tokio::time::timeout(Duration::from_secs(20), …)`, run each and assert it returns Ok:
    - `import_accounts_full_encrypted_bytes(v2 blob of a store with one account named "imported-bytes", Some(pass))`;
    - `import_accounts_full_encrypted_file(path to a v2 blob of a store with one account named "imported-file", written into the TestHome, Some(pass))`;
    - `import_accounts_slim_text(<slim payload with one API-key account named "imported-slim">)`. API-key accounts need no network refresh; build it with the existing slim encoder from a store with one `AuthData::ApiKey` account.

    Then assert the final store has exactly 4 accounts (1 seeded + 3 imported), each summary has `imported_count == 1`, and running the bytes import a second time returns `imported_count == 0`, `skipped_count == 1`.
  - `truncated_inputs_error_without_panic`: for every length 0..=60 of a valid v2 blob's prefix, and every length 0..=50 of a valid v1 blob's prefix, `decode_full(prefix, Some("correct horse battery"))` returns Err without panicking. Prefixes of 45–49 bytes for v2 must give "invalid or truncated".
- [ ] **Step 2: Run them and confirm they fail.** `cargo test full_` (or the test module name) → FAIL.
- [ ] **Step 3: Implement.**
  - v2 layout and AAD per §3.2: the AAD is `&out[..4+1+4+16+24]`; use `cipher.encrypt(nonce, Payload { msg, aad })`.
  - `decode_full` checks the size cap, then `len >= 5` and the magic, then dispatches on byte 4:
    - v1 → require `len > 45`, then the legacy path (ignores the passphrase);
    - v2 → require `len > 49` ("Encrypted file is invalid or truncated"), check the passphrase is non-empty, check the iterations range, then derive and decrypt with AAD;
    - other → the existing "Unsupported" error.
  - `derive_encryption_key(passphrase, salt, iterations)` gains an iterations parameter.
  - Export commands call `validate_new_passphrase` first.
- [ ] **Step 4: Run the tests and confirm they pass.** `cargo test` PASS. Note that `web.rs` won't compile until Task 6 updates its call sites; do the minimal compile fix there in this task by passing `args.passphrase` through, and leave the rest of Task 6 for Task 6.
- [ ] **Step 5: Commit.** `git commit -m "feat: passphrase-protected v2 full backups with legacy v1 import"`

### Task 6: Web server authentication, limits and headers (§3.1, web side of §3.2)

**Files:**
- Modify: `src-tauri/src/web.rs`
- Modify: `src-tauri/src/bin/codex-web.rs`
- Modify: `src-tauri/Cargo.toml` (add `subtle = "2"`; the lockfile resolves 2.6.1)
- Modify: `src-tauri/Cargo.lock`. CI uses `--locked`. Run `cargo build` and commit the lockfile; the diff must be only the root package's new `"subtle"` dependency line.

**Interfaces:**
- Consumes: Task 5 command signatures.
- Produces:
  - `pub fn run_lan_server(host: &str, port: u16, token: String) -> anyhow::Result<()>`
  - `pub fn resolve_web_token(env_value: Option<String>) -> anyhow::Result<String>`: `None` → generate 32 random bytes as base64url; `Some(v)` → validate (≥32 chars, ≥8 distinct) or Err "CODEX_SWITCHER_WEB_TOKEN must be at least 32 characters with at least 8 distinct characters".
  - `fn authorize(headers: &[tiny_http::Header], token: &str) -> Result<(), (u16, &'static str)>`
  - `fn read_body_limited(reader: impl Read, content_length: Option<usize>, max: usize) -> Result<Vec<u8>, (u16, &'static str)>`
  - `fn parse_json_body(bytes: &[u8]) -> Result<Value, (u16, &'static str)>`: an empty or whitespace body gives `{}` (current behavior); invalid JSON gives `(400, "invalid JSON")`.
  - `async fn invoke_web_command(command: &str, payload: Value) -> Result<Value, (u16, String)>`: the `_` arm (unknown or removed commands) gives `(404, "Unsupported web command: …")`; command errors give `(400, msg)`. `handle_request` responds with that status.
  - `fn static_security_headers() -> Vec<Header>`
  - `const MAX_BODY_BYTES: usize`
  - Web arg structs: `ExportEncryptedArgs { passphrase: String }`; `UploadEncryptedArgs` gains `passphrase: Option<String>`.

- [ ] **Step 1: Write failing tests** in `web.rs` `#[cfg(test)] mod tests`, building `Vec<Header>` via `Header::from_bytes`. With `T` being a valid 43-char token:

  | Headers | Expected |
  |---|---|
  | no `Authorization` | `Err((401, _))` |
  | `Bearer wrong` | 401 |
  | `Bearer T` + `Content-Type: application/json` | Ok |
  | `Bearer T` + `Content-Type: text/plain` | 415 |
  | `Bearer T` + JSON + `Origin: http://evil.example` + `Host: 192.168.1.5:3210` | 403 |
  | `Origin: http://192.168.1.5:3210` + `Host: 192.168.1.5:3210` | Ok |
  | `Origin: HTTP://MyBox.local:3210` + `Host: mybox.local:3210` | Ok |
  | `Origin: null` | 403 |
  | `Origin` present, no `Host` | 403 |
  | no `Authorization` + `text/plain` + foreign `Origin` | 401 (token checked first) |

  `read_body_limited`:
  - `content_length = Some(MAX+1)` → 413 without reading (pass a reader that panics on read);
  - a streamed reader of MAX+1 bytes with `None` length → 413;
  - MAX bytes → Ok.

  `invoke_web_command`:
  - `"export_accounts_slim_text"`, `"add_account_from_file"` and `"nonexistent"` → `Err((404, msg))` with msg containing "Unsupported web command";
  - `parse_json_body(b"{not json")` → `Err((400, "invalid JSON"))`; `parse_json_body(b"  ")` → `Ok(json!({}))`;
  - `"export_accounts_full_encrypted_bytes"` with a short passphrase (inside a `TestHome`) → Err "at least 12".

  `static_security_headers()` contains CSP with `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`.

  `resolve_web_token`:
  - `None` → length 43, base64url charset;
  - `Some("a".repeat(40))` → Err;
  - `Some(31 chars)` → Err;
  - `Some(valid 40-char mixed)` → Ok.
- [ ] **Step 2: Run them and confirm they fail.** `cargo test web::` → FAIL.
- [ ] **Step 3: Implement.**
  - `handle_request` for `POST /api/invoke/*` runs `authorize` → `read_body_limited` → JSON parse (400 on failure) → dispatch.
  - Every early return responds via `respond_json(status, {"error": msg})`.
  - Add `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` to `respond_json`; add `static_security_headers()` to `serve_file`.
  - Constant-time compare: `subtle::ConstantTimeEq`, with the length check folded in (compare `provided.as_bytes().ct_eq(token.as_bytes())`, which yields false on a length mismatch).
  - Remove the `export_accounts_slim_text` and `add_account_from_file` match arms, their imports, and the now-unused `FileImportArgs` struct (web.rs:~76-80); otherwise it's a dead-code warning.
  - `codex-web.rs`: `let token = resolve_web_token(std::env::var("CODEX_SWITCHER_WEB_TOKEN").ok())?;`, then pass it to `run_lan_server`.
  - In `run_lan_server`, print `Open: http://{display_host}:{port}/#token={token}`, where `display_host` is `localhost` if the host is `0.0.0.0`, followed by the line "Listening on all interfaces — replace localhost with this machine's LAN or tailnet address".
- [ ] **Step 4: Run the tests and confirm they pass.** `cargo test` PASS.
- [ ] **Step 5: Manual smoke.** Set up without echoing the token:
  - `pnpm build && (cd src-tauri && cargo build --bin codex-web)`
  - `T=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')`
  - Run the binary directly. Don't run it via `cargo run` under a fake HOME, because that would re-download crates. `HOME=$(mktemp -d) CODEX_SWITCHER_WEB_TOKEN="$T" CODEX_SWITCHER_WEB_PORT=3299 src-tauri/target/debug/codex-web >/dev/null 2>&1 &`, then `sleep 1`.

  Then run:
  - `curl -s -o /dev/null -w '%{http_code}' -XPOST localhost:3299/api/invoke/list_accounts` → `401`
  - the same with `-H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{}'` → `200`
  - the same with `-H 'Content-Type: text/plain'` → `415`
  - `export_accounts_slim_text` with auth → `404`
  - `curl -s -D - -o /dev/null localhost:3299/` (GET; the server answers HEAD with 405) includes `content-security-policy`

  Kill the server afterwards. Record the outputs in the task report.
- [ ] **Step 6: Commit.** `git commit -m "fix: require bearer token for LAN web API and harden responses"`

### Task 7: Frontend — web token, passphrase modal, web slim-export guard (§3.1 frontend, §3.2 UI)

**Files:**
- Modify: `src/lib/platform.ts`
- Create: `src/components/BackupPassphraseModal.tsx`
- Modify: `src/components/index.ts` (export the modal)
- Modify: `src/App.tsx` (`handleExportFullFile` ~:1187, `handleImportFullFile` ~:1201, `handleExportSlimText` ~:1132)
- Create: `tests/webToken.test.ts`
- Modify: `package.json` (add `"test:web-token": "node --experimental-strip-types --test tests/webToken.test.ts"`)

**Interfaces:**
- Consumes: Task 5/6 backend argument names: `passphrase` (export, required), `passphrase` (import, optional), and web `contentsBase64`.
- Produces:
  - `export function extractTokenFromHash(hash: string): string | null`
  - `export function webAuthErrorMessage(status: number): string | null`. Returns the exact §3.1 401 copy for 401, else null.
  - `export function isValidNewPassphrase(p: string): boolean`, which is `[...p].length >= 12`. The modal uses it for the submit gate.
  - `exportFullBackupFile(passphrase: string): Promise<boolean>`
  - `importFullBackupFile(passphrase?: string): Promise<ImportAccountsSummary | null>`
  - `<BackupPassphraseModal mode="export" | "import" isOpen onSubmit={(p: string) => void} onClose />`

- [ ] **Step 1: Write failing tests** in `tests/webToken.test.ts` (node:test + assert, importing from `../src/lib/platform.ts` the way existing tests import their libs):
  - `extractTokenFromHash("#token=abc")` → `"abc"`
  - `("#foo=1&token=abc")` → `"abc"`
  - `("")` and `("#foo=1")` → null
  - `("#token=a%2Bb")` → `"a+b"`
  - `("#token=")` → null
  - `webAuthErrorMessage(401)` equals `"Web access token missing or invalid — reopen the URL printed by codex-web"`; `webAuthErrorMessage(400)` → null.
  - `invokeBackend` (web branch). Stub `globalThis.fetch` to record its init and return `new Response("", {status: 401})`, and stub `globalThis.sessionStorage` with a Map-backed object containing the token `"tok"`. Then assert that `invokeBackend("list_accounts")` rejects with the exact 401 message, and that the recorded `headers.Authorization === "Bearer tok"`. Ensure `isTauriRuntime()` is false (no `window.__TAURI_INTERNALS__`); if `window` is undefined in node, the web branch must still work with `globalThis`.
  - `isValidNewPassphrase` (pure helper exported from the same module): `"abcdefghijkl"` → true; `"😀😀😀😀😀😀"` (6 scalars, `.length` 12) → false; `"ééééééééééé1"` → true.

  If importing `platform.ts` pulls Tauri modules at load time, move the two pure helpers into a new `src/lib/webToken.ts`, re-export them from `platform.ts`, and import the new file in the test.
- [ ] **Step 2: Run it and confirm it fails.** `pnpm test:web-token` → FAIL.
- [ ] **Step 3: Implement.**
  - Module init (outside Tauri, guarded by `typeof window !== "undefined"`): run `extractTokenFromHash(location.hash)`; if non-null, set `sessionStorage` (in try/catch), then `history.replaceState(null, "", location.pathname + location.search)`.
  - `invokeBackend` (web branch): add `Authorization: Bearer ${token}` when a token is stored. On `!response.ok`, prefer `webAuthErrorMessage(status)` over `payload.error`.
  - `exportFullBackupFile(passphrase)`: Tauri invokes `{ path, passphrase }`; web invokes `{ passphrase }`.
  - `importFullBackupFile(passphrase?)`: Tauri `{ path, passphrase: passphrase || null }`; web `{ contentsBase64, passphrase: passphrase || null }`.
  - Modal: follow `SettingsModal.tsx` structure and styling classes. Export mode has two password inputs (`autocomplete="new-password"`), a submit button disabled until `isValidNewPassphrase(p)` and the two match, and inline helper text "At least 12 characters. You will need this passphrase to restore the backup." Import mode has one input (`autocomplete="current-password"`) with the hint "Leave blank for backups made before this version". Clear state when `isOpen` turns false. Never `console.log` the value.
  - `App.tsx`: the full export/import buttons open the modal; its `onSubmit` calls the existing handlers with the passphrase.
    - In `handleExportFullFile` and `handleImportFullFile`, the failure toast must carry the backend message: `` `Full export failed: ${err instanceof Error ? err.message : String(err)}` ``, and likewise for import. That way §4's "This backup is passphrase-protected", "Passphrase must be at least 12 characters" and the wrong-passphrase error reach the user.
    - Keep `console.error` of the error object; it never contains the passphrase.
  - The modal in export mode shows the inline error "Passphrase must be at least 12 characters" when the input is non-empty and `!isValidNewPassphrase`, and "Passphrases do not match" when the confirm field differs. In `handleExportSlimText`, if `!isTauriRuntime()`, show the toast "Slim export is unavailable in web mode; use the encrypted full backup" (error style) and return before calling the backend.
- [ ] **Step 4: Run all gates.** `pnpm test:web-token` PASS; all other `tests/*.test.ts` PASS; `pnpm exec tsc --noEmit` clean; `pnpm build` succeeds.
- [ ] **Step 5: Commit.** `git commit -m "feat: web token auth and backup passphrase UI"`

### Task 8: Tauri CSP (§3.7) and Windows shortcut launch (§3.9)

**Files:**
- Modify: `src-tauri/tauri.conf.json` (`app.security`)
- Modify: `src-tauri/src/commands/process.rs:~1326-1332`

These are bundled because each is a few lines of config/platform code with build-only verification.

- [ ] **Step 1: Set the CSP.** Set `app.security.csp` to the exact §3.7 string, `"devCsp": null` and `"freezePrototype": true`. Keep any other existing keys.
- [ ] **Step 2: Verify the bundle.**
  - `pnpm build`, then `grep -c '<script' dist/index.html dist/tray.html`: every match must have `type="module"` with `src=`; there must be no inline script bodies (`grep -n '<script>' dist/*.html` → empty).
  - `cd src-tauri && cargo build` succeeds; Tauri validates the conf schema at build time.
- [ ] **Step 3: Fix the Windows launcher.** Replace the body of `open_windows_shortcut` per §3.9:
  - `let explorer = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows")).join("explorer.exe");` (fully qualified: `process.rs` doesn't import `PathBuf`)
  - `Command::new(explorer).arg(path).creation_flags(CREATE_NO_WINDOW).spawn().is_ok()`
  - Add a comment explaining why the exit code is ignored.

  Check it compiles for Windows if the target is installed (`rustup target list --installed | grep windows`): `cargo check --target x86_64-pc-windows-msvc` may fail on non-Rust deps, so `cargo check --target x86_64-pc-windows-gnu --lib` is best effort. If neither works, note "Windows not compiled locally" in the report; CI covers it.
- [ ] **Step 4: Commit.** `git commit -m "fix: enable strict webview CSP and launch Windows shortcuts without cmd.exe"`

### Task 9: CI/release hardening (§3.8)

**Files:**
- Modify: `.github/workflows/build.yml`, `.github/workflows/pull-request-validation.yml`, `.github/workflows/linux-startup-tests.yml`, `.github/workflows/updater-tests.yml`
- Create: `.github/dependabot.yml`
- Modify: `package.json` (`packageManager`)
- Check: `tests/updaterToolchain.test.ts`. If it asserts workflow contents such as `version: 9` or action tags, update it in lockstep.

- [ ] **Step 1: Resolve SHAs.** For each action in use, run `gh api repos/{owner}/{repo}/commits/{ref} -q .sha`:
  - `actions/checkout` `v4` and `v5`
  - `actions/setup-node` `v4` and `v7` (if `v7` doesn't resolve, use the latest existing major and note it)
  - `pnpm/action-setup` `v4`
  - `dtolnay/rust-toolchain` `stable`
  - `tauri-apps/tauri-action` `v0`

  Then replace every `uses: X@ref` with `uses: X@<sha> # <ref>`.
- [ ] **Step 2: Edit `build.yml`.**
  - Add top-level `permissions: {}` and job-level `permissions: contents: write` on the release job.
  - Checkout: `persist-credentials: false`, plus a comment on the release-note step about private forks.
  - "Determine tag": move `inputs.version`, `github.ref_name` and `github.event_name` into `env:` (`INPUT_VERSION`, `REF_NAME`, `EVENT_NAME`), pick the tag in bash, validate it with `[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "::error::invalid version tag"; exit 1; }`, then write it to `$GITHUB_OUTPUT`.
  - "Determine release note": add `EVENT_NAME: ${{ github.event_name }}` to **this step's own** `env:` (step env doesn't carry over from "Determine tag"), use `"$EVENT_NAME"` in the script, and use the delimiter `delim="EOF_$(openssl rand -hex 16)"`.
  - Install: `pnpm install --frozen-lockfile`.
  - Remove `version: 9` from `pnpm/action-setup` in every workflow.
  - In other workflows, add top-level `permissions: contents: read` where it's absent.
- [ ] **Step 3: Set `packageManager`.**
  - Find the earliest pnpm version that honors `allowBuilds` (check pnpm's changelog or docs via `npm view pnpm versions` plus the release notes). Choose the newest stable in that line.
  - Run `corepack pnpm@<ver> install --frozen-lockfile`, or `npx pnpm@<ver> install --frozen-lockfile`. It must succeed with `git diff --exit-code pnpm-lock.yaml`.
  - If no version both honors `allowBuilds` and keeps the lockfile unchanged, apply the §6 risk-2 fallback instead: add `"pnpm": { "onlyBuiltDependencies": ["esbuild"] }` to `package.json`, keep `pnpm/action-setup` without `version` but set `packageManager` to a 9.x/10.x version that passes `--frozen-lockfile`. Document which branch was taken in the commit body.
- [ ] **Step 4: Add `.github/dependabot.yml`:** version 2, `package-ecosystem: "github-actions"`, `directory: "/"`, `schedule.interval: "weekly"`.
- [ ] **Step 5: Verify.**
  - `python3 -c 'import yaml,sys;[yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml .github/dependabot.yml` exits 0.
  - `grep -nE 'uses: [^ ]+@(v[0-9]+|stable|main)\b' .github/workflows/*.yml` → empty.
  - `grep -n '\${{' .github/workflows/build.yml` → every hit is inside `env:`, `with:`, `if:` or `matrix`, never on a `run:` line or inside a `run: |` block. Check this with `awk` over run blocks, or by inspection, and include the evidence in the report.
  - `pnpm test:updater` PASS.
- [ ] **Step 6: Commit.** `git commit -m "ci: pin actions, block workflow script injection, enforce pnpm build policy"`

### Task 10: README (§3.10)

**Files:**
- Modify: `README.md`: the LAN/web section (around the lines mentioning `pnpm lan`/LAN/Tailscale), plus a **new `## Backups` section** right after it. No backup section exists today; the feature bullet at line ~20 may get a one-phrase "passphrase-protected" tweak.

- [ ] **Step 1: Update the docs.** Write the §3.10 content: the token URL, a "keep it secret" warning, the browser history caveat, `CODEX_SWITCHER_WEB_TOKEN` (≥32 chars), cleartext HTTP with a recommendation for `tailscale serve` or `ssh -L`, slim export unavailable in web mode, the backup passphrase requirement (≥12), that old `.cswf` files still import (leave the passphrase blank) but are protected only by a key that is public in the source, and the advice to re-export old backups with a passphrase and delete the old files. Don't include any real token or the legacy constant.
- [ ] **Step 2: Commit.** `git commit -m "docs: document LAN token auth and backup passphrases"`

### Task 11: Whole-branch verification

- [ ] **Step 1: Run every gate.**
  - `cd src-tauri && cargo test && cargo clippy --all-targets 2>&1 | grep -c '^warning'`. Compare the count to base, which is measured with `git stash`-free `git worktree add /tmp/base c357686` or by recording it before Task 1.
  - `pnpm exec tsc --noEmit && pnpm build`, then every `tests/*.test.ts`.
- [ ] **Step 2: Run the acceptance greps** from Tasks 2, 3 and 9. Each must give its expected result.
- [ ] **Step 3: Walk the spec §1 SC table** and write one line per SC naming the test or evidence that proves it. This becomes the PR's verification section.
- [ ] **Step 4: Draft the PR body** at `docs/superpowers/plans/2026-10-17-security-hardening-pr.md`. It is not committed; the coordinator uses it for `gh pr create --body-file`. Sections:
  1. Summary (findings fixed, with A# refs).
  2. Breaking/behavior changes for users:
     - the web token URL;
     - slim export removed from web mode;
     - backups need a passphrase, and v1 still imports.
  3. SC verification lines from Step 3.
  4. Task 6 smoke outputs (status codes only; no token).
  5. CSP check: the result of running the desktop production build (`pnpm tauri build --debug`, or `pnpm tauri dev` with a prod-like CSP if a bundle build isn't feasible) and confirming the main window and tray render. If it wasn't run, say so explicitly.
  6. Follow-ups and limitations:
     - A16 updater endpoint, which needs an owner decision and key;
     - the store lock is in-process only (desktop + `codex-web` running at once isn't covered);
     - recommended repo settings (protected `release` environment with required reviewers for the signing secrets);
     - which pnpm branch Task 9 took;
     - Windows not compiled locally, if that's true.
