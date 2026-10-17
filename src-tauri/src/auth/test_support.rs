//! Thread-local filesystem isolation for current-thread async command tests.

use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;

thread_local! {
    static TEST_HOME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

pub(crate) fn home_dir() -> Result<PathBuf> {
    TEST_HOME
        .with(|home| home.borrow().clone())
        .context("TestHome must be installed before filesystem access")
}

pub(crate) struct TestHome {
    root: PathBuf,
}

impl TestHome {
    pub(crate) fn new() -> Self {
        assert!(home_dir().is_err(), "test homes must not be nested");
        let root =
            std::env::temp_dir().join(format!("codex-switcher-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        TEST_HOME.with(|home| *home.borrow_mut() = Some(root.clone()));
        Self { root }
    }

    /// Handle that lets another thread use this same fake home.
    pub(crate) fn share(&self) -> SharedTestHome {
        SharedTestHome {
            root: self.root.clone(),
        }
    }
}

/// Send-able handle to a `TestHome` root; install it on a worker thread.
pub(crate) struct SharedTestHome {
    root: PathBuf,
}

impl SharedTestHome {
    pub(crate) fn install(&self) -> SharedGuard {
        assert!(home_dir().is_err(), "thread already has a test home");
        TEST_HOME.with(|home| *home.borrow_mut() = Some(self.root.clone()));
        SharedGuard
    }
}

/// Clears the thread-local home on drop; never deletes anything.
pub(crate) struct SharedGuard;

impl Drop for SharedGuard {
    fn drop(&mut self) {
        TEST_HOME.with(|home| *home.borrow_mut() = None);
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        TEST_HOME.with(|home| *home.borrow_mut() = None);
        // Only remove the unique temporary directory created by this fixture.
        let _ = fs::remove_dir_all(&self.root);
    }
}
