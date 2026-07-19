//! Strict, candidate-root-only migration loading for SQL cutoff parity tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// One regular UTF-8 SQL migration loaded from an explicitly supplied root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationFile {
    /// Zero-based position in lexicographic basename order.
    pub ordinal: usize,
    /// Absolute or caller-relative path returned by joining the explicit root.
    pub path: PathBuf,
    /// UTF-8 basename, including the `.sql` suffix.
    pub basename: String,
    /// Leading ASCII-decimal migration timestamp/version before the first `_`.
    pub timestamp: String,
    /// Complete UTF-8 SQL source.
    pub sql: String,
}

impl MigrationFile {
    /// Returns whether this migration follows another in the loaded chain.
    #[must_use]
    pub fn follows(&self, other: &Self) -> bool {
        self.ordinal > other.ordinal
    }
}

/// Loads every direct regular `.sql` file from `root` in strict basename order.
///
/// The caller must resolve the candidate root before calling this function. This
/// module never consults environment variables and never falls back to the active
/// migration directory.
pub fn read_migrations(root: &Path) -> Result<Vec<MigrationFile>, String> {
    let metadata = fs::metadata(root).map_err(|error| {
        format!(
            "explicit migration root {} must exist and be readable: {error}",
            root.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "explicit migration root {} must be a directory",
            root.display()
        ));
    }

    let entries = fs::read_dir(root).map_err(|error| {
        format!(
            "explicit migration root {} must be readable: {error}",
            root.display()
        )
    })?;
    let mut candidates = Vec::new();
    for entry_result in entries {
        let entry = entry_result.map_err(|error| {
            format!(
                "an entry under explicit migration root {} could not be read: {error}",
                root.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("sql") {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "migration candidate {} file type could not be read: {error}",
                path.display()
            )
        })?;
        if !file_type.is_file() {
            return Err(format!(
                "migration candidate {} must be a direct regular file (symlinks are rejected)",
                path.display()
            ));
        }
        let basename = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("migration basename under {} must be UTF-8", root.display()))?;
        let timestamp = validate_migration_basename(&basename)?;
        candidates.push((basename, timestamp, path));
    }

    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if candidates.is_empty() {
        return Err(format!(
            "explicit migration root {} must contain at least one direct regular .sql file",
            root.display()
        ));
    }

    let mut seen_timestamps = BTreeSet::new();
    let mut migrations = Vec::with_capacity(candidates.len());
    for (ordinal, (basename, timestamp, path)) in candidates.into_iter().enumerate() {
        if !seen_timestamps.insert(timestamp.clone()) {
            return Err(format!(
                "explicit migration root {} contains duplicate migration timestamp {timestamp}",
                root.display()
            ));
        }
        let sql = fs::read_to_string(&path).map_err(|error| {
            format!(
                "migration {} must be readable UTF-8: {error}",
                path.display()
            )
        })?;
        if sql.trim().is_empty() {
            return Err(format!(
                "migration {} must not be empty or whitespace-only",
                path.display()
            ));
        }
        migrations.push(MigrationFile {
            ordinal,
            path,
            basename,
            timestamp,
            sql,
        });
    }

    Ok(migrations)
}

/// Validates `<ASCII decimal>_<description>.sql` and returns its timestamp.
pub fn validate_migration_basename(basename: &str) -> Result<String, String> {
    if basename.as_bytes().contains(&b'/') || basename.as_bytes().contains(&b'\\') {
        return Err(format!(
            "migration basename {basename:?} must not contain a path separator"
        ));
    }
    let stem = basename.strip_suffix(".sql").ok_or_else(|| {
        format!("migration basename {basename:?} must end with the lowercase .sql suffix")
    })?;
    let (timestamp, description) = stem.split_once('_').ok_or_else(|| {
        format!("migration basename {basename:?} must use <ASCII decimal>_<description>.sql")
    })?;
    if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "migration basename {basename:?} must start with a non-empty ASCII-decimal timestamp"
        ));
    }
    if description.is_empty() {
        return Err(format!(
            "migration basename {basename:?} must include a non-empty description"
        ));
    }
    if description.starts_with('.') || description.ends_with('.') {
        return Err(format!(
            "migration basename {basename:?} has an invalid description"
        ));
    }
    Ok(timestamp.to_owned())
}
