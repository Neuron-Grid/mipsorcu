use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolloverOutcome {
    Skipped,
    Sealed(RolloverArchive),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloverArchive {
    pub archive_path: PathBuf,
    pub sha256_hex: String,
    pub line_count: usize,
    pub first_occurred_at: Option<String>,
    pub last_occurred_at: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSweepOutcome {
    pub deleted_archives: Vec<SweptArchive>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweptArchive {
    pub archive_path: PathBuf,
    pub sha256_hex: Option<String>,
    pub line_count: Option<usize>,
    pub size_bytes: u64,
}
