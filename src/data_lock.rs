//! Process-wide ownership of the data directory, independent of listening ports.
use anyhow::{Context, Result};
use std::{fs::File, path::Path};

/// Keep this guard alive while any runtime task can mutate the directory.
/// On Linux, flock locks the directory inode, so aliases and symlinks cannot
/// bypass it and no sentinel file needs to be deleted after a crash.
/// Prosody itself does not participate in this lock.
pub struct DataDirectoryGuard {
    _directory: File,
}

impl DataDirectoryGuard {
    pub fn acquire(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).context("cannot create data directory")?;
        let directory = File::open(root).context("cannot open data directory")?;
        directory.try_lock().context(
            "cannot exclusively lock data directory; another rust-xmpp process may be using it",
        )?;
        Ok(Self {
            _directory: directory,
        })
    }
}
