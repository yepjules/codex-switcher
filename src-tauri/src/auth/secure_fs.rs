//! Atomic, private (0600/0700) file writes for secrets and settings.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rand::RngCore;

/// Retry `rename` on transient sharing violations (Windows: Codex or antivirus
/// holding the destination open). 1 initial attempt plus up to `retries` more.
fn rename_with_retry(
    from: &Path,
    to: &Path,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
    retries: u32,
    delay: Duration,
) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let retryable = e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(32);
                if !retryable || attempt >= retries {
                    return Err(e);
                }
                attempt += 1;
                std::thread::sleep(delay);
            }
        }
    }
}

fn create_dir_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))
    }
}

/// Create `path` if missing and, on Unix, force mode 0700 even when it already
/// exists (migrates older 0755 installs). Only call for directories this app
/// owns (`~/.codex-switcher`), never `~/.codex`.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    create_dir_private(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to restrict directory: {}", path.display()))?;
    }
    Ok(())
}

/// Atomically write `bytes` to `path` with mode 0600 (Unix).
///
/// If `path` is a symlink (e.g. a dotfile-managed `~/.codex/auth.json`), the
/// link is resolved and the target is replaced, so the link itself survives.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let target: PathBuf = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(path)
            .with_context(|| format!("Failed to resolve symlink: {}", path.display()))?,
        _ => path.to_path_buf(),
    };

    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    create_dir_private(&parent)?;

    let file_name = target
        .file_name()
        .context("Path has no file name")?
        .to_string_lossy()
        .into_owned();
    let mut rnd = [0u8; 8];
    rand::rng().fill_bytes(&mut rnd);
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = parent.join(format!(".{file_name}.tmp-{}-{hex}", std::process::id()));

    let result = (|| -> Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("Failed to create temp file: {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("Failed to write temp file: {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync temp file: {}", tmp.display()))?;
        drop(file);

        let retries = if cfg!(windows) { 5 } else { 0 };
        rename_with_retry(
            &tmp,
            &target,
            |a, b| fs::rename(a, b),
            retries,
            Duration::from_millis(50),
        )
        .with_context(|| format!("Failed to replace file: {}", target.display()))?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    {
        // Best effort: persist the rename.
        if let Ok(dir) = fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("secure-fs-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn writes_file_with_0600_and_no_temp_left() {
        let d = tmpdir();
        let f = d.join("a.json");
        write_private_file(&f, b"hello").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"hello");
        assert_eq!(mode(&f), 0o600);
        for e in fs::read_dir(&d).unwrap() {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!n.starts_with(".a.json.tmp-"), "leftover temp {n}");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn replaces_existing_file_atomically() {
        let d = tmpdir();
        let f = d.join("a.json");
        write_private_file(&f, b"a").unwrap();
        write_private_file(&f, b"b").unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"b");
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn creates_missing_parent_with_0700() {
        let d = tmpdir();
        let sub = d.join("sub");
        write_private_file(&sub.join("a.json"), b"x").unwrap();
        assert_eq!(mode(&sub), 0o700);
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_tightens_existing_0755() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn writes_through_symlink_and_preserves_link() {
        let d = tmpdir();
        let target = d.join("target");
        let link = d.join("link");
        fs::write(&target, b"old").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_private_file(&link, b"x").unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "x");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rename_retry_recovers_after_sharing_violation() {
        let calls = Cell::new(0);
        let r = rename_with_retry(
            Path::new("a"),
            Path::new("b"),
            |_, _| {
                calls.set(calls.get() + 1);
                if calls.get() <= 2 {
                    Err(std::io::Error::from_raw_os_error(32))
                } else {
                    Ok(())
                }
            },
            5,
            Duration::ZERO,
        );
        assert!(r.is_ok());
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn rename_retry_gives_up_after_retries() {
        let calls = Cell::new(0);
        let r = rename_with_retry(
            Path::new("a"),
            Path::new("b"),
            |_, _| {
                calls.set(calls.get() + 1);
                Err(std::io::ErrorKind::PermissionDenied.into())
            },
            5,
            Duration::ZERO,
        );
        assert!(r.is_err());
        assert_eq!(calls.get(), 6);
    }

    #[test]
    fn rename_retry_does_not_retry_other_errors() {
        let calls = Cell::new(0);
        let r = rename_with_retry(
            Path::new("a"),
            Path::new("b"),
            |_, _| {
                calls.set(calls.get() + 1);
                Err(std::io::ErrorKind::NotFound.into())
            },
            5,
            Duration::ZERO,
        );
        assert!(r.is_err());
        assert_eq!(calls.get(), 1);
    }
}
