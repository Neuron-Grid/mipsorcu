//! Candidate-aware SQL cutoff migration-root resolution.

use std::env::{self, VarError};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Environment variable that selects the migration root under test.
pub const MIGRATION_ROOT_ENV: &str = "SQL_CUTOFF_MIGRATION_ROOT";

/// Environment variable that selects the SQL cutoff profile.
pub const PROFILE_ENV: &str = "SQL_CUTOFF_PROFILE";

/// Environment variable that enables formal, no-default resolution.
pub const FORMAL_ENV: &str = "SQL_CUTOFF_FORMAL";

const DEFAULT_MIGRATION_ROOT: &str = "supabase/migrations";

/// Supported migration layouts for SQL cutoff parity validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlCutoffProfile {
    /// The frozen full migration chain through migration 1460.
    LegacyHead1460,
    /// The candidate v0.2 baseline migration layout.
    BaselineV02,
}

impl SqlCutoffProfile {
    /// Returns the canonical profile identifier used by the environment contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyHead1460 => "legacy-head-1460",
            Self::BaselineV02 => "baseline-v0.2",
        }
    }

    fn parse(value: &str) -> Result<Self, ResolverError> {
        match value {
            "legacy-head-1460" => Ok(Self::LegacyHead1460),
            "baseline-v0.2" => Ok(Self::BaselineV02),
            _ => Err(ResolverError::new(format!(
                "{PROFILE_ENV} has unsupported value {value:?}; expected legacy-head-1460 or baseline-v0.2"
            ))),
        }
    }
}

impl Display for SqlCutoffProfile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Read-only snapshot of the SQL cutoff resolver environment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolverEnvironment {
    migration_root: Option<PathBuf>,
    profile: Option<String>,
    formal: Option<String>,
}

impl ResolverEnvironment {
    /// Creates an environment snapshot for pure resolver calls and fixtures.
    #[must_use]
    pub fn new(
        migration_root: Option<PathBuf>,
        profile: Option<String>,
        formal: Option<String>,
    ) -> Self {
        Self {
            migration_root,
            profile,
            formal,
        }
    }

    /// Reads the resolver variables without mutating process environment state.
    pub fn read() -> Result<Self, ResolverError> {
        Ok(Self {
            migration_root: env::var_os(MIGRATION_ROOT_ENV).map(PathBuf::from),
            profile: read_unicode_environment(PROFILE_ENV)?,
            formal: read_unicode_environment(FORMAL_ENV)?,
        })
    }
}

/// Pure inputs used to resolve exactly one migration candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverInputs {
    manifest_dir: PathBuf,
    explicit_migration_root: Option<PathBuf>,
    explicit_profile: Option<SqlCutoffProfile>,
    environment: ResolverEnvironment,
}

impl ResolverInputs {
    /// Creates resolver inputs without reading or changing process environment state.
    #[must_use]
    pub fn new(
        manifest_dir: PathBuf,
        explicit_migration_root: Option<PathBuf>,
        explicit_profile: Option<SqlCutoffProfile>,
        environment: ResolverEnvironment,
    ) -> Self {
        Self {
            manifest_dir,
            explicit_migration_root,
            explicit_profile,
            environment,
        }
    }
}

/// A validated migration root, its profile, and candidate-only migration files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMigrationRoot {
    root: PathBuf,
    profile: SqlCutoffProfile,
    migration_files: Vec<PathBuf>,
    assertion_context: String,
    used_non_formal_defaults: bool,
}

impl ResolvedMigrationRoot {
    /// Returns the canonical candidate root selected by the resolver.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the validated profile for the selected candidate.
    #[must_use]
    pub const fn profile(&self) -> SqlCutoffProfile {
        self.profile
    }

    /// Returns the sorted regular SQL files found directly in the candidate root.
    #[must_use]
    pub fn migration_files(&self) -> &[PathBuf] {
        &self.migration_files
    }

    /// Returns context that must be included in candidate assertions and errors.
    #[must_use]
    pub fn assertion_context(&self) -> &str {
        &self.assertion_context
    }

    /// Reports whether non-formal active-root and legacy-profile defaults were used.
    #[must_use]
    pub const fn used_non_formal_defaults(&self) -> bool {
        self.used_non_formal_defaults
    }
}

/// Fail-closed error returned by migration-root resolution and validation.
#[derive(Debug)]
pub struct ResolverError {
    message: String,
}

impl ResolverError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl Display for ResolverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ResolverError {}

/// Resolves and validates one candidate from pure inputs.
pub fn resolve(inputs: &ResolverInputs) -> Result<ResolvedMigrationRoot, ResolverError> {
    let manifest_dir = canonical_directory(&inputs.manifest_dir, "CARGO_MANIFEST_DIR")?;
    let formal = parse_formal(inputs.environment.formal.as_deref())?;
    let environment_profile = inputs
        .environment
        .profile
        .as_deref()
        .map(SqlCutoffProfile::parse)
        .transpose()?;
    let profile = merge_profile(inputs.explicit_profile, environment_profile)?;
    let has_root =
        inputs.explicit_migration_root.is_some() || inputs.environment.migration_root.is_some();

    validate_completeness(formal, has_root, profile.is_some())?;

    let used_non_formal_defaults = !formal && !has_root && profile.is_none();
    let (root, root_source) = if used_non_formal_defaults {
        (
            canonical_migration_root(&manifest_dir.join(DEFAULT_MIGRATION_ROOT), "default root")?,
            "non-formal default",
        )
    } else {
        merge_root(
            &manifest_dir,
            inputs.explicit_migration_root.as_deref(),
            inputs.environment.migration_root.as_deref(),
        )?
    };
    let profile = match profile {
        Some(profile) => profile,
        None if used_non_formal_defaults => SqlCutoffProfile::LegacyHead1460,
        None => {
            return Err(ResolverError::new(
                "internal resolver invariant: migration profile was not selected".to_owned(),
            ));
        }
    };
    let migration_files = validate_sql_files(&root)?;
    let assertion_context = if used_non_formal_defaults {
        format!(
            "non-formal defaults used: {MIGRATION_ROOT_ENV}={}; {PROFILE_ENV}={profile}; candidate root only",
            root.display()
        )
    } else {
        format!(
            "explicit SQL cutoff selection: root={} ({root_source}); profile={profile}; formal={formal}; candidate root only",
            root.display()
        )
    };

    Ok(ResolvedMigrationRoot {
        root,
        profile,
        migration_files,
        assertion_context,
        used_non_formal_defaults,
    })
}

/// Reads the resolver environment and resolves one candidate without mutation.
pub fn resolve_from_environment(
    manifest_dir: &Path,
    explicit_migration_root: Option<&Path>,
    explicit_profile: Option<SqlCutoffProfile>,
) -> Result<ResolvedMigrationRoot, ResolverError> {
    let inputs = ResolverInputs::new(
        manifest_dir.to_path_buf(),
        explicit_migration_root.map(Path::to_path_buf),
        explicit_profile,
        ResolverEnvironment::read()?,
    );
    resolve(&inputs)
}

fn read_unicode_environment(name: &'static str) -> Result<Option<String>, ResolverError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(ResolverError::new(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

fn parse_formal(value: Option<&str>) -> Result<bool, ResolverError> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(ResolverError::new(format!(
            "{FORMAL_ENV} has unsupported value {other:?}; expected 0, 1, or unset"
        ))),
    }
}

fn merge_profile(
    explicit: Option<SqlCutoffProfile>,
    environment: Option<SqlCutoffProfile>,
) -> Result<Option<SqlCutoffProfile>, ResolverError> {
    match (explicit, environment) {
        (Some(explicit), Some(environment)) if explicit != environment => Err(ResolverError::new(
            format!("explicit profile {explicit} does not match {PROFILE_ENV}={environment}"),
        )),
        (Some(profile), _) | (_, Some(profile)) => Ok(Some(profile)),
        (None, None) => Ok(None),
    }
}

fn validate_completeness(
    formal: bool,
    has_root: bool,
    has_profile: bool,
) -> Result<(), ResolverError> {
    match (formal, has_root, has_profile) {
        (true, false, false) => Err(ResolverError::new(format!(
            "{FORMAL_ENV}=1 requires {MIGRATION_ROOT_ENV} (or an explicit root) and {PROFILE_ENV} (or an explicit profile)"
        ))),
        (true, false, true) => Err(ResolverError::new(format!(
            "{FORMAL_ENV}=1 requires {MIGRATION_ROOT_ENV} or an explicit root"
        ))),
        (true, true, false) => Err(ResolverError::new(format!(
            "{FORMAL_ENV}=1 requires {PROFILE_ENV} or an explicit profile"
        ))),
        (false, true, false) | (false, false, true) => Err(ResolverError::new(format!(
            "non-formal explicit selection must specify both {MIGRATION_ROOT_ENV} (or an explicit root) and {PROFILE_ENV} (or an explicit profile)"
        ))),
        _ => Ok(()),
    }
}

fn merge_root(
    manifest_dir: &Path,
    explicit: Option<&Path>,
    environment: Option<&Path>,
) -> Result<(PathBuf, &'static str), ResolverError> {
    match (explicit, environment) {
        (Some(explicit), Some(environment)) => {
            let explicit = canonical_migration_root(
                &resolve_against_manifest(manifest_dir, explicit)?,
                "explicit migration root",
            )?;
            let environment = canonical_migration_root(
                &resolve_against_manifest(manifest_dir, environment)?,
                MIGRATION_ROOT_ENV,
            )?;
            if explicit != environment {
                return Err(ResolverError::new(format!(
                    "explicit migration root {} does not match {MIGRATION_ROOT_ENV}={} after canonicalization",
                    explicit.display(),
                    environment.display()
                )));
            }
            Ok((explicit, "explicit argument + environment"))
        }
        (Some(explicit), None) => Ok((
            canonical_migration_root(
                &resolve_against_manifest(manifest_dir, explicit)?,
                "explicit migration root",
            )?,
            "explicit argument",
        )),
        (None, Some(environment)) => Ok((
            canonical_migration_root(
                &resolve_against_manifest(manifest_dir, environment)?,
                MIGRATION_ROOT_ENV,
            )?,
            "environment",
        )),
        (None, None) => Err(ResolverError::new(
            "internal resolver invariant: migration root was not selected".to_owned(),
        )),
    }
}

fn resolve_against_manifest(manifest_dir: &Path, root: &Path) -> Result<PathBuf, ResolverError> {
    if root.as_os_str().is_empty() {
        return Err(ResolverError::new(
            "migration root must not be an empty path".to_owned(),
        ));
    }
    Ok(if root.is_absolute() {
        root.to_path_buf()
    } else {
        manifest_dir.join(root)
    })
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ResolverError> {
    if path.as_os_str().is_empty() {
        return Err(ResolverError::new(format!(
            "{label} must not be an empty path"
        )));
    }
    let metadata = fs::metadata(path).map_err(|error| {
        ResolverError::new(format!(
            "{label} {} is not readable: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ResolverError::new(format!(
            "{label} {} is not a directory",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(|error| {
        ResolverError::new(format!(
            "{label} {} cannot be canonicalized: {error}",
            path.display()
        ))
    })
}

fn canonical_migration_root(path: &Path, label: &str) -> Result<PathBuf, ResolverError> {
    canonical_directory(path, label)
}

fn validate_sql_files(root: &Path) -> Result<Vec<PathBuf>, ResolverError> {
    let entries = fs::read_dir(root).map_err(|error| {
        ResolverError::new(format!(
            "candidate migration root {} cannot be read: {error}",
            root.display()
        ))
    })?;
    let mut sql_files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ResolverError::new(format!(
                "candidate migration root {} contains an unreadable directory entry: {error}",
                root.display()
            ))
        })?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("sql")) {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| {
            ResolverError::new(format!(
                "candidate SQL entry {} has unreadable type metadata: {error}",
                path.display()
            ))
        })?;
        if !file_type.is_file() {
            return Err(ResolverError::new(format!(
                "candidate SQL entry {} is not a regular file",
                path.display()
            )));
        }
        let file = File::open(&path).map_err(|error| {
            ResolverError::new(format!(
                "candidate SQL file {} is not readable: {error}",
                path.display()
            ))
        })?;
        drop(file);
        sql_files.push(path);
    }
    if sql_files.is_empty() {
        return Err(ResolverError::new(format!(
            "candidate migration root {} contains no regular readable .sql files",
            root.display()
        )));
    }
    sql_files.sort();
    Ok(sql_files)
}
