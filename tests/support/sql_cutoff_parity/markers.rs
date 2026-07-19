//! Strict marker-block parsing and profile-specific inventory validation.

use std::ops::Range;
use std::path::{Path, PathBuf};

use super::migrations::MigrationFile;
use super::resolver::SqlCutoffProfile;

/// One marker family and its exact standalone boundary lines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkerFamily {
    /// Stable family name without the comment prefix or boundary suffix.
    pub name: &'static str,
    /// Exact standalone start line after surrounding whitespace is removed.
    pub start: &'static str,
    /// Exact standalone end line after surrounding whitespace is removed.
    pub end: &'static str,
}

/// The nine marker families in the frozen legacy-head-1460 inventory.
pub const LEGACY_MARKER_FAMILIES: [MarkerFamily; 9] = [
    MarkerFamily {
        name: "FORBIDDEN_AUDIT_METADATA_KEYS",
        start: "-- FORBIDDEN_AUDIT_METADATA_KEYS_START",
        end: "-- FORBIDDEN_AUDIT_METADATA_KEYS_END",
    },
    MarkerFamily {
        name: "FORBIDDEN_LEDGER_PAYLOAD_KEYS",
        start: "-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_START",
        end: "-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_END",
    },
    MarkerFamily {
        name: "ACTION_ALLOWLIST",
        start: "-- ACTION_ALLOWLIST_START",
        end: "-- ACTION_ALLOWLIST_END",
    },
    MarkerFamily {
        name: "REQUIRED_KEY",
        start: "-- REQUIRED_KEY_START",
        end: "-- REQUIRED_KEY_END",
    },
    MarkerFamily {
        name: "NOTIFIER_KIND_ALLOWLIST",
        start: "-- NOTIFIER_KIND_ALLOWLIST_START",
        end: "-- NOTIFIER_KIND_ALLOWLIST_END",
    },
    MarkerFamily {
        name: "INCIDENT_CATEGORY_ALLOWLIST",
        start: "-- INCIDENT_CATEGORY_ALLOWLIST_START",
        end: "-- INCIDENT_CATEGORY_ALLOWLIST_END",
    },
    MarkerFamily {
        name: "INCIDENT_TYPE_ALLOWLIST",
        start: "-- INCIDENT_TYPE_ALLOWLIST_START",
        end: "-- INCIDENT_TYPE_ALLOWLIST_END",
    },
    MarkerFamily {
        name: "SEVERITY_ALLOWLIST",
        start: "-- SEVERITY_ALLOWLIST_START",
        end: "-- SEVERITY_ALLOWLIST_END",
    },
    MarkerFamily {
        name: "NOTIFICATION_RESULT_ALLOWLIST",
        start: "-- NOTIFICATION_RESULT_ALLOWLIST_START",
        end: "-- NOTIFICATION_RESULT_ALLOWLIST_END",
    },
];

/// The baseline-only trigger vocabulary marker family.
pub const TRIGGER_VOCABULARY_FAMILY: MarkerFamily = MarkerFamily {
    name: "TRIGGER_VOCABULARY",
    start: "-- TRIGGER_VOCABULARY_START",
    end: "-- TRIGGER_VOCABULARY_END",
};

/// One fully paired marker occurrence in one candidate migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkerOccurrence {
    /// Marker family name.
    pub family: &'static str,
    /// Candidate migration that physically carries this block.
    pub path: PathBuf,
    /// Candidate migration ordinal in basename order.
    pub migration_ordinal: usize,
    /// Byte range from the start marker through the end marker line.
    pub block_range: Range<usize>,
    /// Exact bytes between the marker boundary lines.
    pub payload: String,
}

/// One profile inventory entry after physical/effective occurrence selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkerInventoryEntry {
    /// Marker family name.
    pub family: &'static str,
    /// Carrier selected by the profile contract.
    pub carrier: PathBuf,
    /// Physical occurrences represented by this inventory entry.
    pub occurrences: usize,
}

/// Validates the exact marker-family/occurrence contract for a profile.
pub fn validate_profile_marker_inventory(
    migrations: &[MigrationFile],
    profile: SqlCutoffProfile,
) -> Result<Vec<MarkerInventoryEntry>, String> {
    if migrations.is_empty() {
        return Err("marker inventory requires at least one candidate migration".to_owned());
    }

    let mut inventory = Vec::new();
    match profile {
        SqlCutoffProfile::LegacyHead1460 => {
            for family in LEGACY_MARKER_FAMILIES {
                let occurrence = latest_effective_occurrence(migrations, family)?;
                inventory.push(MarkerInventoryEntry {
                    family: family.name,
                    carrier: occurrence.path,
                    occurrences: 1,
                });
            }
            let trigger_count = marker_occurrences(migrations, TRIGGER_VOCABULARY_FAMILY)?.len();
            if trigger_count != 0 {
                return Err(format!(
                    "legacy-head-1460 requires 9 effective marker families and no TRIGGER_VOCABULARY blocks; found {trigger_count} trigger blocks"
                ));
            }
            if inventory.len() != 9 {
                return Err(format!(
                    "legacy-head-1460 requires exactly 9 effective marker families; found {}",
                    inventory.len()
                ));
            }
        }
        SqlCutoffProfile::BaselineV02 => {
            for family in LEGACY_MARKER_FAMILIES {
                let occurrences = marker_occurrences(migrations, family)?;
                if occurrences.len() != 1 {
                    return Err(format!(
                        "baseline-v0.2 requires exactly one physical {} block; found {}",
                        family.name,
                        occurrences.len()
                    ));
                }
                let occurrence = occurrences.into_iter().next().ok_or_else(|| {
                    format!(
                        "{} occurrence disappeared after count validation",
                        family.name
                    )
                })?;
                inventory.push(MarkerInventoryEntry {
                    family: family.name,
                    carrier: occurrence.path,
                    occurrences: 1,
                });
            }

            let trigger_occurrences = marker_occurrences(migrations, TRIGGER_VOCABULARY_FAMILY)?;
            if trigger_occurrences.len() != 2 {
                return Err(format!(
                    "baseline-v0.2 requires exactly two physical TRIGGER_VOCABULARY blocks; found {}",
                    trigger_occurrences.len()
                ));
            }
            let trigger_carrier = common_carrier(&trigger_occurrences)?;
            inventory.push(MarkerInventoryEntry {
                family: TRIGGER_VOCABULARY_FAMILY.name,
                carrier: trigger_carrier,
                occurrences: 2,
            });
            let physical_count = inventory
                .iter()
                .map(|entry| entry.occurrences)
                .sum::<usize>();
            if inventory.len() != 10 || physical_count != 11 {
                return Err(format!(
                    "baseline-v0.2 requires 10 marker families / 11 physical blocks; found {} families / {physical_count} blocks",
                    inventory.len()
                ));
            }
        }
    }
    Ok(inventory)
}

/// Returns every physical block for `family` across only the supplied candidate.
pub fn marker_occurrences(
    migrations: &[MigrationFile],
    family: MarkerFamily,
) -> Result<Vec<MarkerOccurrence>, String> {
    let mut occurrences = Vec::new();
    for migration in migrations {
        occurrences.extend(marker_occurrences_in_migration(migration, family)?);
    }
    Ok(occurrences)
}

/// Returns the sole block in the latest migration that carries `family`.
pub fn latest_effective_occurrence(
    migrations: &[MigrationFile],
    family: MarkerFamily,
) -> Result<MarkerOccurrence, String> {
    let occurrences = marker_occurrences(migrations, family)?;
    let latest_ordinal = occurrences
        .iter()
        .map(|occurrence| occurrence.migration_ordinal)
        .max()
        .ok_or_else(|| format!("candidate has no standalone {} block", family.name))?;
    let mut latest = occurrences
        .into_iter()
        .filter(|occurrence| occurrence.migration_ordinal == latest_ordinal);
    let occurrence = latest
        .next()
        .ok_or_else(|| format!("candidate has no effective {} block", family.name))?;
    if latest.next().is_some() {
        return Err(format!(
            "effective {} carrier {} contains multiple physical blocks",
            family.name,
            occurrence.path.display()
        ));
    }
    Ok(occurrence)
}

/// Parses paired standalone marker lines from one migration, rejecting orphans.
pub fn marker_occurrences_in_migration(
    migration: &MigrationFile,
    family: MarkerFamily,
) -> Result<Vec<MarkerOccurrence>, String> {
    let lines = line_spans(&migration.sql);
    let mut open: Option<&LineSpan<'_>> = None;
    let mut occurrences = Vec::new();

    for line in &lines {
        if line.trimmed == family.start {
            if open.is_some() {
                return Err(format!(
                    "nested or duplicate {} start marker in {}",
                    family.name,
                    migration.path.display()
                ));
            }
            open = Some(line);
            continue;
        }
        if line.trimmed != family.end {
            continue;
        }
        let start = open.take().ok_or_else(|| {
            format!(
                "orphan {} end marker in {}",
                family.name,
                migration.path.display()
            )
        })?;
        occurrences.push(MarkerOccurrence {
            family: family.name,
            path: migration.path.clone(),
            migration_ordinal: migration.ordinal,
            block_range: start.start..line.full_end,
            payload: migration.sql[start.full_end..line.start].to_owned(),
        });
    }

    if open.is_some() {
        return Err(format!(
            "unclosed {} start marker in {}",
            family.name,
            migration.path.display()
        ));
    }
    Ok(occurrences)
}

/// Returns whether `content` contains `marker` as an exact standalone line.
#[must_use]
pub fn has_standalone_marker(content: &str, marker: &str) -> bool {
    content.lines().any(|line| line.trim() == marker)
}

fn common_carrier(occurrences: &[MarkerOccurrence]) -> Result<PathBuf, String> {
    let first = occurrences
        .first()
        .ok_or_else(|| "marker carrier selection requires an occurrence".to_owned())?;
    if occurrences
        .iter()
        .any(|occurrence| occurrence.path != first.path)
    {
        return Err(
            "TRIGGER_VOCABULARY physical blocks must share one baseline carrier".to_owned(),
        );
    }
    Ok(first.path.clone())
}

#[derive(Debug)]
struct LineSpan<'a> {
    start: usize,
    full_end: usize,
    trimmed: &'a str,
}

fn line_spans(content: &str) -> Vec<LineSpan<'_>> {
    let mut offset = 0usize;
    content
        .split_inclusive('\n')
        .map(|line| {
            let start = offset;
            offset = offset.saturating_add(line.len());
            LineSpan {
                start,
                full_end: offset,
                trimmed: line.trim(),
            }
        })
        .collect()
}

/// Returns the marker block payload for the latest effective carrier.
pub fn latest_effective_payload(
    migrations: &[MigrationFile],
    family: MarkerFamily,
) -> Result<String, String> {
    latest_effective_occurrence(migrations, family).map(|occurrence| occurrence.payload)
}

/// Returns the carrier path for the latest effective marker occurrence.
pub fn latest_effective_carrier(
    migrations: &[MigrationFile],
    family: MarkerFamily,
) -> Result<&Path, String> {
    let occurrence = latest_effective_occurrence(migrations, family)?;
    migrations
        .iter()
        .find(|migration| {
            migration.ordinal == occurrence.migration_ordinal && migration.path == occurrence.path
        })
        .map(|migration| migration.path.as_path())
        .ok_or_else(|| format!("effective {} carrier is outside candidate", family.name))
}
