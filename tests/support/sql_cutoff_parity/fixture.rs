//! RAII throwaway migration roots for parity mutation fixtures.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::migrations::validate_migration_basename;

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
const MAX_CREATE_ATTEMPTS: u64 = 1_024;

/// A unique, test-local migration root removed when dropped.
#[derive(Debug)]
pub struct ThrowawayMigrationRoot {
    path: PathBuf,
    closed: bool,
}

impl ThrowawayMigrationRoot {
    /// Creates a unique directory below the operating-system temporary root.
    pub fn new(label: &str) -> Result<Self, String> {
        validate_label(label)?;
        let temporary_root = std::env::temp_dir();
        let process_id = std::process::id();
        let initial_sequence = NEXT_FIXTURE_ID.fetch_add(MAX_CREATE_ATTEMPTS, Ordering::Relaxed);

        for offset in 0..MAX_CREATE_ATTEMPTS {
            let sequence = initial_sequence.saturating_add(offset);
            let path = temporary_root.join(format!(
                "mipsorcu-sql-cutoff-t1-{label}-{process_id}-{sequence}"
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        closed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "throwaway migration root {} could not be created: {error}",
                        path.display()
                    ));
                }
            }
        }

        Err(format!(
            "could not allocate a unique throwaway migration root for label {label:?} after {MAX_CREATE_ATTEMPTS} attempts"
        ))
    }

    /// Returns the explicit root path to pass to candidate-only helpers.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates one new migration without overwriting an existing fixture file.
    pub fn write_migration(&self, basename: &str, sql: &str) -> Result<PathBuf, String> {
        self.write_migration_in(Path::new(""), basename, sql)
    }

    /// Creates a safe relative child directory under this throwaway root.
    pub fn create_directory(&self, relative: &Path) -> Result<PathBuf, String> {
        validate_relative_path(relative)?;
        if self.closed {
            return Err("throwaway migration root has already been explicitly closed".to_owned());
        }
        let path = self.path.join(relative);
        fs::create_dir_all(&path).map_err(|error| {
            format!(
                "throwaway child directory {} could not be created: {error}",
                path.display()
            )
        })?;
        Ok(path)
    }

    /// Creates one migration under a safe relative child root without overwrite.
    pub fn write_migration_in(
        &self,
        relative_root: &Path,
        basename: &str,
        sql: &str,
    ) -> Result<PathBuf, String> {
        if !relative_root.as_os_str().is_empty() {
            validate_relative_path(relative_root)?;
        }
        validate_migration_basename(basename)?;
        if sql.trim().is_empty() {
            return Err(format!(
                "throwaway migration {basename:?} must not be empty or whitespace-only"
            ));
        }
        if self.closed {
            return Err("throwaway migration root has already been explicitly closed".to_owned());
        }
        let directory = if relative_root.as_os_str().is_empty() {
            self.path.clone()
        } else {
            self.create_directory(relative_root)?
        };
        let path = directory.join(basename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                format!(
                    "throwaway migration {} could not be created without overwrite: {error}",
                    path.display()
                )
            })?;
        file.write_all(sql.as_bytes()).map_err(|error| {
            format!(
                "throwaway migration {} could not be written: {error}",
                path.display()
            )
        })?;
        file.flush().map_err(|error| {
            format!(
                "throwaway migration {} could not be flushed: {error}",
                path.display()
            )
        })?;
        Ok(path)
    }

    /// Creates one arbitrary non-empty fixture file at a safe relative path.
    pub fn write_file(&self, relative_file: &Path, content: &str) -> Result<PathBuf, String> {
        validate_relative_path(relative_file)?;
        if content.is_empty() {
            return Err("throwaway fixture file must not be empty".to_owned());
        }
        if self.closed {
            return Err("throwaway migration root has already been explicitly closed".to_owned());
        }
        let parent = relative_file
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            self.create_directory(parent)?;
        }
        let path = self.path.join(relative_file);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                format!(
                    "throwaway fixture file {} could not be created without overwrite: {error}",
                    path.display()
                )
            })?;
        file.write_all(content.as_bytes()).map_err(|error| {
            format!(
                "throwaway fixture file {} could not be written: {error}",
                path.display()
            )
        })?;
        file.flush().map_err(|error| {
            format!(
                "throwaway fixture file {} could not be flushed: {error}",
                path.display()
            )
        })?;
        Ok(path)
    }

    /// Removes the fixture now and reports cleanup failures.
    pub fn close(mut self) -> Result<(), String> {
        if self.closed {
            return Err("throwaway migration root has already been explicitly closed".to_owned());
        }
        fs::remove_dir_all(&self.path).map_err(|error| {
            format!(
                "throwaway migration root {} could not be removed: {error}",
                self.path.display()
            )
        })?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for ThrowawayMigrationRoot {
    fn drop(&mut self) {
        if !self.closed {
            let _cleanup_result = fs::remove_dir_all(&self.path);
        }
    }
}

fn validate_label(label: &str) -> Result<(), String> {
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(format!(
            "throwaway migration root label {label:?} must be 1..=64 ASCII alphanumeric, '-' or '_' bytes"
        ));
    }
    Ok(())
}

fn validate_relative_path(relative: &Path) -> Result<(), String> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "throwaway child path {} must be a non-empty relative path without traversal",
            relative.display()
        ));
    }
    Ok(())
}
