//! Account management Tauri commands

use crate::auth::{
    add_account, create_chatgpt_account_from_refresh_token, ensure_chatgpt_tokens_fresh_locked,
    get_active_account, import_from_auth_json, import_from_auth_json_contents, load_accounts,
    mutate_accounts, read_current_auth, remove_account, set_active_account, switch_to_account,
    sync_active_account_tokens, touch_account, AUTH_OPERATION_LOCK,
};
use crate::types::{AccountInfo, AccountsStore, AuthData, ImportAccountsSummary, StoredAccount};

use super::process::ensure_codex_not_running;

use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use futures::{stream, StreamExt};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const SLIM_EXPORT_PREFIX: &str = "css1.";
const SLIM_FORMAT_VERSION: u8 = 1;
const SLIM_AUTH_API_KEY: u8 = 0;
const SLIM_AUTH_CHATGPT: u8 = 1;

const FULL_FILE_MAGIC: &[u8; 4] = b"CSWF";
const FULL_FILE_VERSION_V1: u8 = 1;
const FULL_FILE_VERSION_V2: u8 = 2;
const FULL_SALT_LEN: usize = 16;
const FULL_NONCE_LEN: usize = 24;
const FULL_KDF_ITERATIONS_V1: u32 = 210_000;
const FULL_KDF_ITERATIONS_V2: u32 = 600_000;
const MIN_KDF_ITERATIONS: u32 = 100_000;
const MAX_KDF_ITERATIONS: u32 = 2_000_000;
const MIN_PASSPHRASE_CHARS: usize = 12;
/// v1 header: magic(4) + version(1) + salt + nonce.
const FULL_V1_HEADER_LEN: usize = 4 + 1 + FULL_SALT_LEN + FULL_NONCE_LEN;
/// v2 header: magic(4) + version(1) + iterations(4) + salt + nonce; passed as AEAD AAD.
const FULL_V2_HEADER_LEN: usize = 4 + 1 + 4 + FULL_SALT_LEN + FULL_NONCE_LEN;
/// Read-only compatibility for v1 backups; never used for new exports.
const LEGACY_V1_PASSPHRASE: &str = "gT7kQ9mV2xN4pL8sR1dH6zW3cB5yF0uJ_aE7nK2tP9vM4rX1";

const MAX_IMPORT_JSON_BYTES: u64 = 2 * 1024 * 1024;
const MAX_IMPORT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const SLIM_IMPORT_CONCURRENCY: usize = 6;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SlimPayload {
    #[serde(rename = "v")]
    version: u8,
    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    active_name: Option<String>,
    #[serde(rename = "c")]
    accounts: Vec<SlimAccountPayload>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SlimAccountPayload {
    #[serde(rename = "n")]
    name: String,
    #[serde(rename = "t")]
    auth_type: u8,
    #[serde(rename = "k", skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
    #[serde(rename = "r", skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// List all accounts with their info
#[tauri::command]
pub async fn list_accounts() -> Result<Vec<AccountInfo>, String> {
    let store = load_accounts().map_err(|e| e.to_string())?;
    let active_id = store.active_account_id.as_deref();

    let accounts: Vec<AccountInfo> = store
        .accounts
        .iter()
        .map(|a| {
            let mut info = AccountInfo::from_stored(a, active_id);
            super::usage::apply_cached_account_metadata(&mut info);
            info
        })
        .collect();

    Ok(accounts)
}

/// Get the currently active account
#[tauri::command]
pub async fn get_active_account_info() -> Result<Option<AccountInfo>, String> {
    let store = load_accounts().map_err(|e| e.to_string())?;
    let active_id = store.active_account_id.as_deref();

    if let Some(active) = get_active_account().map_err(|e| e.to_string())? {
        let mut info = AccountInfo::from_stored(&active, active_id);
        super::usage::apply_cached_account_metadata(&mut info);
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

/// Add an account from an auth.json file
#[tauri::command]
pub async fn add_account_from_file(path: String, name: String) -> Result<AccountInfo, String> {
    // Import from the file
    let account = import_from_auth_json(&path, name).map_err(|e| e.to_string())?;

    // Add to storage
    let stored = add_account(account).map_err(|e| e.to_string())?;

    let store = load_accounts().map_err(|e| e.to_string())?;
    let active_id = store.active_account_id.as_deref();

    Ok(AccountInfo::from_stored(&stored, active_id))
}

/// Add an account from uploaded auth.json contents.
pub async fn add_account_from_auth_json_text(
    name: String,
    contents: String,
) -> Result<AccountInfo, String> {
    let account = import_from_auth_json_contents(&contents, name).map_err(|e| e.to_string())?;
    let stored = add_account(account).map_err(|e| e.to_string())?;

    let store = load_accounts().map_err(|e| e.to_string())?;
    let active_id = store.active_account_id.as_deref();

    Ok(AccountInfo::from_stored(&stored, active_id))
}

/// Switch to a different account
#[tauri::command]
pub async fn switch_account(account_id: String) -> Result<(), String> {
    switch_account_by_id(&account_id).await
}

pub async fn switch_account_by_id(account_id: &str) -> Result<(), String> {
    let _auth_guard = AUTH_OPERATION_LOCK.lock().await;
    let store = load_accounts().map_err(|e| e.to_string())?;

    let target_index = store
        .accounts
        .iter()
        .position(|account| account.id == account_id)
        .ok_or_else(|| format!("Account not found: {account_id}"))?;

    if store.active_account_id.as_deref() == Some(account_id) {
        return Ok(());
    }

    ensure_codex_not_running()?;

    // ChatGPT rotates single-use refresh tokens. Preserve the latest token
    // before replacing auth.json, otherwise switching back restores a stale one.
    let mut target = store.accounts[target_index].clone();
    if let Some(auth) = read_current_auth().map_err(|e| e.to_string())? {
        let refreshed_target = mutate_accounts(|store| {
            sync_active_account_tokens(store, &auth);
            Ok(store.accounts.iter().find(|a| a.id == account_id).cloned())
        })
        .map_err(|e| e.to_string())?;
        if let Some(refreshed_target) = refreshed_target {
            target = refreshed_target;
        }
    }

    let account = ensure_chatgpt_tokens_fresh_locked(&target)
        .await
        .map_err(|e| e.to_string())?;

    // Write to ~/.codex/auth.json
    switch_to_account(&account).map_err(|e| e.to_string())?;

    // Update the active account in our store
    set_active_account(account_id).map_err(|e| e.to_string())?;

    // Update last_used_at
    touch_account(account_id).map_err(|e| e.to_string())?;

    // Restart Antigravity background process if it is running
    // This allows it to pick up the new authorization file seamlessly
    if let Ok(pids) = find_antigravity_processes() {
        for pid in pids {
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .output();
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            }
        }
    }

    Ok(())
}

/// Remove an account
#[tauri::command]
pub async fn delete_account(account_id: String) -> Result<(), String> {
    // Serialize with switch_account so auth.json is never written for a deleted account.
    let _auth_guard = AUTH_OPERATION_LOCK.lock().await;
    remove_account(&account_id).map_err(|e| e.to_string())?;
    Ok(())
}

/// Rename an account
#[tauri::command]
pub async fn rename_account(account_id: String, new_name: String) -> Result<(), String> {
    crate::auth::storage::update_account_metadata(&account_id, Some(new_name), None, None, None)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Export minimal account config as a compact text string.
/// For ChatGPT accounts, only refresh token is exported.
#[tauri::command]
pub async fn export_accounts_slim_text() -> Result<String, String> {
    let store = load_accounts().map_err(|e| e.to_string())?;
    encode_slim_payload_from_store(&store).map_err(|e| e.to_string())
}

/// Import minimal account config from a compact text string, skipping existing accounts.
#[tauri::command]
pub async fn import_accounts_slim_text(payload: String) -> Result<ImportAccountsSummary, String> {
    let slim_payload = decode_slim_payload(&payload).map_err(|e| format!("{e:#}"))?;
    let total_in_payload = slim_payload.accounts.len();

    let current = load_accounts().map_err(|e| e.to_string())?;
    let existing_names: HashSet<String> = current.accounts.iter().map(|a| a.name.clone()).collect();

    let imported = build_store_from_slim_payload(slim_payload, &existing_names)
        .await
        .map_err(|e| {
            format!(
                "{e:#}\nHint: Slim import needs network access to refresh ChatGPT tokens. You can use Full encrypted file import when offline."
            )
        })?;
    validate_imported_store(&imported).map_err(|e| format!("{e:#}"))?;

    // `existing_names` came from a pre-network snapshot; the merge re-checks
    // duplicates against the fresh store under the lock, so that is safe.
    let summary = mutate_accounts(|current| {
        let (merged, summary) = merge_accounts_store(std::mem::take(current), imported);
        *current = merged;
        Ok(summary)
    })
    .map_err(|e| e.to_string())?;
    Ok(ImportAccountsSummary {
        total_in_payload,
        imported_count: summary.imported_count,
        skipped_count: total_in_payload.saturating_sub(summary.imported_count),
    })
}

/// Export full account config as an encrypted file.
#[tauri::command]
pub async fn export_accounts_full_encrypted_file(
    path: String,
    passphrase: String,
) -> Result<(), String> {
    validate_new_passphrase(&passphrase).map_err(|e| e.to_string())?;
    let store = load_accounts().map_err(|e| e.to_string())?;
    let encrypted = encode_full_v2_blocking(store, passphrase).await?;
    write_encrypted_file(&path, &encrypted).map_err(|e| e.to_string())?;
    Ok(())
}

/// Export full account config as encrypted bytes for browser clients.
pub async fn export_accounts_full_encrypted_bytes(passphrase: String) -> Result<Vec<u8>, String> {
    validate_new_passphrase(&passphrase).map_err(|e| e.to_string())?;
    let store = load_accounts().map_err(|e| e.to_string())?;
    encode_full_v2_blocking(store, passphrase).await
}

/// PBKDF2 at 600k iterations is CPU-heavy; keep it off the async worker threads.
async fn encode_full_v2_blocking(
    store: AccountsStore,
    passphrase: String,
) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || encode_full_v2(&store, &passphrase, FULL_KDF_ITERATIONS_V2))
        .await
        .map_err(|e| format!("Backup encryption task failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// Key derivation and decryption run on the blocking pool for the same reason.
async fn decode_full_blocking(
    bytes: Vec<u8>,
    passphrase: Option<String>,
) -> Result<AccountsStore, String> {
    tokio::task::spawn_blocking(move || decode_full(&bytes, passphrase.as_deref()))
        .await
        .map_err(|e| format!("Backup decryption task failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// Import full account config from an encrypted file, skipping existing accounts.
#[tauri::command]
pub async fn import_accounts_full_encrypted_file(
    path: String,
    passphrase: Option<String>,
) -> Result<ImportAccountsSummary, String> {
    let encrypted = read_encrypted_file(&path).map_err(|e| e.to_string())?;
    let imported = decode_full_blocking(encrypted, passphrase).await?;
    validate_imported_store(&imported).map_err(|e| e.to_string())?;

    mutate_accounts(|current| {
        let (merged, summary) = merge_accounts_store(std::mem::take(current), imported);
        *current = merged;
        Ok(summary)
    })
    .map_err(|e| e.to_string())
}

/// Import full account config from encrypted bytes uploaded through the browser UI.
pub async fn import_accounts_full_encrypted_bytes(
    bytes: Vec<u8>,
    passphrase: Option<String>,
) -> Result<ImportAccountsSummary, String> {
    let imported = decode_full_blocking(bytes, passphrase).await?;
    validate_imported_store(&imported).map_err(|e| e.to_string())?;

    mutate_accounts(|current| {
        let (merged, summary) = merge_accounts_store(std::mem::take(current), imported);
        *current = merged;
        Ok(summary)
    })
    .map_err(|e| e.to_string())
}

/// Find all running Antigravity codex assistant processes
fn find_antigravity_processes() -> anyhow::Result<Vec<u32>> {
    let mut pids = Vec::new();

    #[cfg(unix)]
    {
        // Use ps with custom format to get the pid and full command line
        let output = std::process::Command::new("ps")
            .args(["-eo", "pid,command"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some((pid_str, command)) = line.split_once(' ') {
                let pid_str = pid_str.trim();
                let command = command.trim();

                // Antigravity processes have a specific path format
                let is_antigravity = (command.contains(".antigravity/extensions/openai.chatgpt")
                    || command.contains(".vscode/extensions/openai.chatgpt"))
                    && (command.ends_with("codex app-server --analytics-default-enabled")
                        || command.contains("/codex app-server"));

                if is_antigravity {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // Use tasklist on Windows
        // For Windows we might need a more precise WMI query to get command line args,
        // but for now we look for codex.exe PIDs and verify they're not ours
        let output = std::process::Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", "IMAGENAME eq codex.exe", "/FO", "CSV", "/NH"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() > 1 {
                let name = parts[0].trim_matches('"').to_lowercase();
                if name == "codex.exe" {
                    let pid_str = parts[1].trim_matches('"');
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    Ok(pids)
}

fn encode_slim_payload_from_store(store: &AccountsStore) -> anyhow::Result<String> {
    let active_name = store.active_account_id.as_ref().and_then(|active_id| {
        store
            .accounts
            .iter()
            .find(|account| account.id == *active_id)
            .map(|account| account.name.clone())
    });

    let slim_accounts = store
        .accounts
        .iter()
        .map(|account| match &account.auth_data {
            AuthData::ApiKey { key } => SlimAccountPayload {
                name: account.name.clone(),
                auth_type: SLIM_AUTH_API_KEY,
                api_key: Some(key.clone()),
                refresh_token: None,
            },
            AuthData::ChatGPT { refresh_token, .. } => SlimAccountPayload {
                name: account.name.clone(),
                auth_type: SLIM_AUTH_CHATGPT,
                api_key: None,
                refresh_token: Some(refresh_token.clone()),
            },
        })
        .collect();

    let payload = SlimPayload {
        version: SLIM_FORMAT_VERSION,
        active_name,
        accounts: slim_accounts,
    };

    let json = serde_json::to_vec(&payload).context("Failed to serialize slim payload")?;
    let compressed = compress_bytes(&json).context("Failed to compress slim payload")?;

    Ok(format!(
        "{SLIM_EXPORT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(compressed)
    ))
}

fn decode_slim_payload(payload: &str) -> anyhow::Result<SlimPayload> {
    let normalized: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.is_empty() {
        anyhow::bail!("Import string is empty");
    }

    let encoded = normalized
        .strip_prefix(SLIM_EXPORT_PREFIX)
        .unwrap_or(&normalized);

    let compressed = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("Invalid slim import string (base64 decode failed)")?;

    let decompressed = decompress_bytes_with_limit(&compressed, MAX_IMPORT_JSON_BYTES)
        .context("Invalid slim import string (decompression failed)")?;

    let parsed: SlimPayload = serde_json::from_slice(&decompressed)
        .context("Invalid slim import string (JSON parse failed)")?;

    validate_slim_payload(&parsed)?;
    Ok(parsed)
}

fn validate_slim_payload(payload: &SlimPayload) -> anyhow::Result<()> {
    if payload.version != SLIM_FORMAT_VERSION {
        anyhow::bail!("Unsupported slim payload version: {}", payload.version);
    }

    let mut names = HashSet::new();

    for account in &payload.accounts {
        if account.name.trim().is_empty() {
            anyhow::bail!("Slim import contains an account with empty name");
        }

        if !names.insert(account.name.clone()) {
            anyhow::bail!(
                "Slim import contains duplicate account name: {}",
                account.name
            );
        }

        match account.auth_type {
            SLIM_AUTH_API_KEY => {
                if account
                    .api_key
                    .as_ref()
                    .map_or(true, |key| key.trim().is_empty())
                {
                    anyhow::bail!("API key is missing for account {}", account.name);
                }
            }
            SLIM_AUTH_CHATGPT => {
                if account
                    .refresh_token
                    .as_ref()
                    .map_or(true, |token| token.trim().is_empty())
                {
                    anyhow::bail!("Refresh token is missing for account {}", account.name);
                }
            }
            _ => {
                anyhow::bail!(
                    "Unsupported auth type {} for account {}",
                    account.auth_type,
                    account.name
                );
            }
        }
    }

    if let Some(active_name) = &payload.active_name {
        if !names.contains(active_name) {
            anyhow::bail!("Slim import references missing active account: {active_name}");
        }
    }

    Ok(())
}

async fn build_store_from_slim_payload(
    payload: SlimPayload,
    existing_names: &HashSet<String>,
) -> anyhow::Result<AccountsStore> {
    let active_name = payload.active_name;
    let import_candidates: Vec<SlimAccountPayload> = payload
        .accounts
        .into_iter()
        .filter(|entry| !existing_names.contains(&entry.name))
        .collect();

    let accounts = restore_slim_accounts(import_candidates).await?;
    let mut active_account_id = None;

    if let Some(active) = active_name {
        active_account_id = accounts
            .iter()
            .find(|account| account.name == active)
            .map(|account| account.id.clone());
    }

    if active_account_id.is_none() {
        active_account_id = accounts.first().map(|a| a.id.clone());
    }

    Ok(AccountsStore {
        version: 1,
        accounts,
        active_account_id,
        masked_account_ids: Vec::new(),
    })
}

async fn restore_slim_accounts(
    entries: Vec<SlimAccountPayload>,
) -> anyhow::Result<Vec<StoredAccount>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut restored = Vec::with_capacity(entries.len());
    let mut tasks = stream::iter(entries.into_iter().map(|entry| async move {
        let account_name = entry.name;
        let account = match entry.auth_type {
            SLIM_AUTH_API_KEY => StoredAccount::new_api_key(
                account_name.clone(),
                entry.api_key.context("API key payload is missing")?,
            ),
            SLIM_AUTH_CHATGPT => {
                let refresh_token = entry
                    .refresh_token
                    .context("Refresh token payload is missing")?;
                create_chatgpt_account_from_refresh_token(account_name.clone(), refresh_token)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to restore ChatGPT account `{account_name}` from refresh token"
                        )
                    })?
            }
            _ => anyhow::bail!("Unsupported auth type in slim payload"),
        };
        Ok::<StoredAccount, anyhow::Error>(account)
    }))
    .buffered(SLIM_IMPORT_CONCURRENCY);

    while let Some(account_result) = tasks.next().await {
        restored.push(account_result?);
    }

    Ok(restored)
}

/// The passphrase must be at least `MIN_PASSPHRASE_CHARS` Unicode scalar values.
fn validate_new_passphrase(passphrase: &str) -> anyhow::Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        anyhow::bail!("Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(())
}

/// v2 layout: "CSWF" | 0x02 | iterations u32 BE | salt[16] | nonce[24] | ciphertext.
/// The 49-byte header is bound to the ciphertext as AEAD associated data.
fn encode_full_v2(
    store: &AccountsStore,
    passphrase: &str,
    iterations: u32,
) -> anyhow::Result<Vec<u8>> {
    let json = serde_json::to_vec(store).context("Failed to serialize account store")?;
    let compressed = compress_bytes(&json).context("Failed to compress account store")?;

    let mut salt = [0u8; FULL_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);

    let mut nonce = [0u8; FULL_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);

    let mut out = Vec::with_capacity(FULL_V2_HEADER_LEN + compressed.len() + 16);
    out.extend_from_slice(FULL_FILE_MAGIC);
    out.push(FULL_FILE_VERSION_V2);
    out.extend_from_slice(&iterations.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), FULL_V2_HEADER_LEN);

    let key = derive_encryption_key(passphrase, &salt, iterations);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: compressed.as_slice(),
                aad: &out[..FULL_V2_HEADER_LEN],
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed to encrypt account store"))?;
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

fn decode_full(file_bytes: &[u8], passphrase: Option<&str>) -> anyhow::Result<AccountsStore> {
    if file_bytes.len() as u64 > MAX_IMPORT_FILE_BYTES {
        anyhow::bail!("Encrypted file is too large");
    }

    if file_bytes.len() < 5 {
        anyhow::bail!("Encrypted file is invalid or truncated");
    }

    if &file_bytes[..4] != FULL_FILE_MAGIC {
        anyhow::bail!("Encrypted file header is invalid");
    }

    let compressed = match file_bytes[4] {
        FULL_FILE_VERSION_V1 => {
            if file_bytes.len() <= FULL_V1_HEADER_LEN {
                anyhow::bail!("Encrypted file is invalid or truncated");
            }
            let salt = &file_bytes[5..5 + FULL_SALT_LEN];
            let nonce = &file_bytes[5 + FULL_SALT_LEN..FULL_V1_HEADER_LEN];
            let ciphertext = &file_bytes[FULL_V1_HEADER_LEN..];
            let key = derive_encryption_key(LEGACY_V1_PASSPHRASE, salt, FULL_KDF_ITERATIONS_V1);
            decrypt_payload(
                &key,
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )?
        }
        FULL_FILE_VERSION_V2 => {
            if file_bytes.len() <= FULL_V2_HEADER_LEN {
                anyhow::bail!("Encrypted file is invalid or truncated");
            }
            let passphrase = passphrase
                .filter(|p| !p.is_empty())
                .ok_or_else(|| anyhow::anyhow!("This backup is passphrase-protected"))?;
            let iterations =
                u32::from_be_bytes([file_bytes[5], file_bytes[6], file_bytes[7], file_bytes[8]]);
            if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&iterations) {
                anyhow::bail!("Encrypted file header is invalid");
            }
            let salt = &file_bytes[9..9 + FULL_SALT_LEN];
            let nonce = &file_bytes[9 + FULL_SALT_LEN..FULL_V2_HEADER_LEN];
            let ciphertext = &file_bytes[FULL_V2_HEADER_LEN..];
            let key = derive_encryption_key(passphrase, salt, iterations);
            decrypt_payload(
                &key,
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &file_bytes[..FULL_V2_HEADER_LEN],
                },
            )?
        }
        version => anyhow::bail!("Unsupported encrypted file version: {version}"),
    };

    let json = decompress_bytes_with_limit(&compressed, MAX_IMPORT_JSON_BYTES)
        .context("Failed to decompress decrypted payload")?;

    let store: AccountsStore =
        serde_json::from_slice(&json).context("Failed to parse decrypted account payload")?;

    Ok(store)
}

fn decrypt_payload(
    key: &[u8; 32],
    nonce: &[u8],
    payload: Payload<'_, '_>,
) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), payload)
        .map_err(|_| anyhow::anyhow!("Failed to decrypt file (wrong passphrase or corrupted file)"))
}

fn derive_encryption_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

fn compress_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(input)?;
    encoder.finish().context("Failed to finalize compression")
}

fn decompress_bytes_with_limit(input: &[u8], max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(input);
    let mut limited = decoder.by_ref().take(max_bytes + 1);
    let mut decompressed = Vec::new();
    limited.read_to_end(&mut decompressed)?;

    if decompressed.len() as u64 > max_bytes {
        anyhow::bail!("Import data is too large");
    }

    Ok(decompressed)
}

fn write_encrypted_file(path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    crate::auth::secure_fs::write_private_file(std::path::Path::new(path), bytes)
        .with_context(|| format!("Failed to write file: {path}"))
}

fn read_encrypted_file(path: &str) -> anyhow::Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Failed to read file metadata: {path}"))?;
    if metadata.len() > MAX_IMPORT_FILE_BYTES {
        anyhow::bail!("Encrypted file is too large");
    }

    fs::read(path).with_context(|| format!("Failed to read file: {path}"))
}

fn validate_imported_store(store: &AccountsStore) -> anyhow::Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();

    for account in &store.accounts {
        if account.id.trim().is_empty() {
            anyhow::bail!("Import contains an account with empty id");
        }
        if account.name.trim().is_empty() {
            anyhow::bail!("Import contains an account with empty name");
        }
        if !ids.insert(account.id.clone()) {
            anyhow::bail!("Import contains duplicate account id: {}", account.id);
        }
        if !names.insert(account.name.clone()) {
            anyhow::bail!("Import contains duplicate account name: {}", account.name);
        }
    }

    if let Some(active_id) = &store.active_account_id {
        if !ids.contains(active_id) {
            anyhow::bail!("Import references a missing active account: {active_id}");
        }
    }

    Ok(())
}

pub(crate) fn merge_accounts_store(
    mut current: AccountsStore,
    imported: AccountsStore,
) -> (AccountsStore, ImportAccountsSummary) {
    let imported_version = imported.version;
    let imported_active_id = imported.active_account_id;
    let total_in_payload = imported.accounts.len();
    let mut imported_count = 0usize;
    let mut existing_ids: HashSet<String> = current.accounts.iter().map(|a| a.id.clone()).collect();
    let mut existing_names: HashSet<String> =
        current.accounts.iter().map(|a| a.name.clone()).collect();

    for account in imported.accounts {
        if existing_ids.contains(&account.id) || existing_names.contains(&account.name) {
            continue;
        }
        existing_ids.insert(account.id.clone());
        existing_names.insert(account.name.clone());
        current.accounts.push(account);
        imported_count += 1;
    }

    current.version = current.version.max(imported_version).max(1);

    let current_active_is_valid = current
        .active_account_id
        .as_ref()
        .is_some_and(|id| current.accounts.iter().any(|a| &a.id == id));

    if !current_active_is_valid {
        if let Some(imported_active) = imported_active_id {
            if current.accounts.iter().any(|a| a.id == imported_active) {
                current.active_account_id = Some(imported_active);
            } else {
                current.active_account_id = current.accounts.first().map(|a| a.id.clone());
            }
        } else {
            current.active_account_id = current.accounts.first().map(|a| a.id.clone());
        }
    }

    (
        current,
        ImportAccountsSummary {
            total_in_payload,
            imported_count,
            skipped_count: total_in_payload.saturating_sub(imported_count),
        },
    )
}

/// Get the list of masked account IDs
#[tauri::command]
pub async fn get_masked_account_ids() -> Result<Vec<String>, String> {
    crate::auth::storage::get_masked_account_ids().map_err(|e| e.to_string())
}

/// Set the list of masked account IDs
#[tauri::command]
pub async fn set_masked_account_ids(ids: Vec<String>) -> Result<(), String> {
    crate::auth::storage::set_masked_account_ids(ids).map_err(|e| e.to_string())
}

#[cfg(test)]
mod backup_tests {
    use super::*;
    use crate::auth::test_support::TestHome;
    use chacha20poly1305::aead::Payload;
    use std::time::Duration;

    const PASS: &str = "correct horse battery";
    const TEST_ITERS: u32 = 100_000;

    fn api_key_store(name: &str) -> AccountsStore {
        AccountsStore {
            accounts: vec![StoredAccount::new_api_key(
                name.into(),
                format!("key-{name}"),
            )],
            ..AccountsStore::default()
        }
    }

    fn v2_blob(name: &str) -> Vec<u8> {
        encode_full_v2(&api_key_store(name), PASS, TEST_ITERS).unwrap()
    }

    /// Legacy v1 layout: magic | 1 | salt | nonce | ct, no AAD.
    fn v1_blob(store: &AccountsStore) -> Vec<u8> {
        let json = serde_json::to_vec(store).unwrap();
        let compressed = compress_bytes(&json).unwrap();
        let salt = [7u8; FULL_SALT_LEN];
        let nonce = [9u8; FULL_NONCE_LEN];
        let key = derive_encryption_key(LEGACY_V1_PASSPHRASE, &salt, FULL_KDF_ITERATIONS_V1);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), compressed.as_slice())
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(FULL_FILE_MAGIC);
        out.push(FULL_FILE_VERSION_V1);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn err_text<T>(r: anyhow::Result<T>) -> String {
        match r {
            Ok(_) => panic!("expected error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn v2_round_trip() {
        let blob = v2_blob("alpha");
        let store = decode_full(&blob, Some(PASS)).unwrap();
        assert_eq!(store.accounts.len(), 1);
        assert_eq!(store.accounts[0].name, "alpha");
    }

    #[test]
    fn v2_wrong_passphrase_fails() {
        let blob = v2_blob("alpha");
        let msg = err_text(decode_full(&blob, Some("another long passphrase")));
        assert!(msg.contains("wrong passphrase"), "{msg}");
    }

    #[test]
    fn v2_missing_passphrase_fails() {
        let blob = v2_blob("alpha");
        for p in [None, Some("")] {
            let msg = err_text(decode_full(&blob, p));
            assert!(msg.contains("passphrase-protected"), "{msg}");
        }
    }

    #[test]
    fn short_passphrase_rejected() {
        let msg = err_text(validate_new_passphrase("short"));
        assert_eq!(msg, "Passphrase must be at least 12 characters");
        assert!(validate_new_passphrase("abcdefghijkl").is_ok());
        assert!(validate_new_passphrase("ééééééééééé1").is_ok());
    }

    #[test]
    fn v1_legacy_still_imports() {
        let blob = v1_blob(&api_key_store("legacy"));
        for p in [None, Some("")] {
            let store = decode_full(&blob, p).unwrap();
            assert_eq!(store.accounts[0].name, "legacy");
        }
    }

    #[test]
    fn v2_iterations_out_of_range_rejected() {
        for bad in [50_000u32, 5_000_000u32] {
            let mut blob = v2_blob("alpha");
            blob[5..9].copy_from_slice(&bad.to_be_bytes());
            let msg = err_text(decode_full(&blob, Some(PASS)));
            assert!(msg.contains("header is invalid"), "{msg}");
        }
    }

    #[test]
    fn v2_header_tamper_fails() {
        let mut blob = v2_blob("alpha");
        blob[5..9].copy_from_slice(&(TEST_ITERS + 1).to_be_bytes());
        let msg = err_text(decode_full(&blob, Some(PASS)));
        assert!(msg.contains("wrong passphrase"), "{msg}");
    }

    #[test]
    fn v2_header_is_bound_as_aad() {
        let blob = v2_blob("alpha");
        let iters = u32::from_be_bytes(blob[5..9].try_into().unwrap());
        let salt = &blob[9..25];
        let nonce = &blob[25..49];
        let key = derive_encryption_key(PASS, salt, iters);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ct = &blob[49..];
        assert!(cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
            .is_err());
        assert!(cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &blob[..49]
                }
            )
            .is_ok());
    }

    #[test]
    fn truncated_inputs_error_without_panic() {
        let v2 = v2_blob("alpha");
        for len in 0..=60usize.min(v2.len()) {
            assert!(decode_full(&v2[..len], Some(PASS)).is_err(), "v2 len {len}");
        }
        for len in 45..=49 {
            let msg = err_text(decode_full(&v2[..len], Some(PASS)));
            assert!(msg.contains("invalid or truncated"), "{len}: {msg}");
        }
        let v1 = v1_blob(&api_key_store("legacy"));
        for len in 0..=50usize.min(v1.len()) {
            assert!(decode_full(&v1[..len], Some(PASS)).is_err(), "v1 len {len}");
        }
    }

    /// The body runs on its own thread (with its own TestHome and runtime) so a
    /// sync-lock deadlock fails the test via `recv_timeout` instead of hanging it.
    #[test]
    fn imports_run_under_store_lock_without_deadlock() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(imports_body);
            let _ = tx.send(outcome.map_err(|_| "import body panicked".to_string()));
        });
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(())) => {}
            Ok(Err(message)) => panic!("{message}"),
            Err(_) => panic!("deadlock: imports did not finish in time"),
        }
    }

    fn imports_body() {
        let _home = TestHome::new();
        crate::auth::seed_accounts_for_test(&api_key_store("seed")).unwrap();

        let bytes_blob = v2_blob("imported-bytes");
        let file_blob = v2_blob("imported-file");
        let file_path = crate::auth::test_support::home_dir()
            .unwrap()
            .join("backup-file.bin");
        fs::write(&file_path, &file_blob).unwrap();
        let slim = encode_slim_payload_from_store(&api_key_store("imported-slim")).unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (a, b, c, again) = runtime.block_on(async {
            let a =
                import_accounts_full_encrypted_bytes(bytes_blob.clone(), Some(PASS.to_string()))
                    .await
                    .unwrap();
            let b = import_accounts_full_encrypted_file(
                file_path.to_string_lossy().into_owned(),
                Some(PASS.to_string()),
            )
            .await
            .unwrap();
            let c = import_accounts_slim_text(slim).await.unwrap();
            let again = import_accounts_full_encrypted_bytes(bytes_blob, Some(PASS.to_string()))
                .await
                .unwrap();
            (a, b, c, again)
        });
        assert_eq!(a.imported_count, 1);
        assert_eq!(b.imported_count, 1);
        assert_eq!(c.imported_count, 1);
        assert_eq!(again.imported_count, 0);
        assert_eq!(again.skipped_count, 1);
        assert_eq!(load_accounts().unwrap().accounts.len(), 4);
    }
}
