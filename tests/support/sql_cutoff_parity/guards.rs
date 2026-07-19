//! Marker-family to effective guard-definition hard gates.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::definitions::latest_definition;
use super::markers::{
    LEGACY_MARKER_FAMILIES, MarkerFamily, marker_occurrences, validate_profile_marker_inventory,
};
use super::migrations::MigrationFile;
use super::resolver::SqlCutoffProfile;

/// One fixed marker-family to canonical guard-function ownership contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkerGuardSpec {
    /// Marker family.
    pub marker: MarkerFamily,
    /// Exact canonical `schema.name(type,...)` identity.
    pub owner_identity: &'static str,
}

/// The normative nine-family to eight-guard mapping.
pub const MARKER_GUARD_SPECS: [MarkerGuardSpec; 9] = [
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[0],
        owner_identity: "public.audit_metadata_has_forbidden_key(jsonb)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[1],
        owner_identity: "public.ledger_payload_has_forbidden_key(jsonb)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[2],
        owner_identity: "public.audit_metadata_has_unknown_key_for_action(text,text,jsonb)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[3],
        owner_identity: "public.audit_metadata_has_missing_required_key_for_action(text,text,jsonb,boolean)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[4],
        owner_identity: "public.audit_metadata_has_invalid_value_for_action(text,text,jsonb)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[5],
        owner_identity: "public.audit_metadata_has_invalid_value_for_action(text,text,jsonb)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[6],
        owner_identity: "public.incident_type_allowed(text)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[7],
        owner_identity: "public.incident_severity_allowed(text)",
    },
    MarkerGuardSpec {
        marker: LEGACY_MARKER_FAMILIES[8],
        owner_identity: "public.incident_notification_result_allowed(text)",
    },
];

/// One validated marker/guard/carrier relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardInventoryEntry {
    /// Marker family.
    pub marker_family: &'static str,
    /// Canonical effective owner identity.
    pub owner_identity: &'static str,
    /// Candidate migration that carries both the marker and owner definition.
    pub carrier: PathBuf,
}

/// Validates profile marker counts and all nine marker-to-eight-guard owners.
pub fn validate_guard_inventory(
    migrations: &[MigrationFile],
    profile: SqlCutoffProfile,
) -> Result<Vec<GuardInventoryEntry>, String> {
    validate_profile_marker_inventory(migrations, profile)?;

    let owner_count = MARKER_GUARD_SPECS
        .iter()
        .map(|spec| spec.owner_identity)
        .collect::<BTreeSet<_>>()
        .len();
    if MARKER_GUARD_SPECS.len() != 9 || owner_count != 8 {
        return Err(format!(
            "normative marker/guard mapping must remain 9 families / 8 guards; found {} / {owner_count}",
            MARKER_GUARD_SPECS.len()
        ));
    }

    let mut inventory = Vec::with_capacity(MARKER_GUARD_SPECS.len());
    for spec in MARKER_GUARD_SPECS {
        let occurrences = marker_occurrences(migrations, spec.marker)?;
        let marker =
            match profile {
                SqlCutoffProfile::LegacyHead1460 => {
                    let latest_ordinal = occurrences
                        .iter()
                        .map(|occurrence| occurrence.migration_ordinal)
                        .max()
                        .ok_or_else(|| {
                            format!("candidate has no effective {} marker", spec.marker.name)
                        })?;
                    let effective = occurrences
                        .into_iter()
                        .filter(|occurrence| occurrence.migration_ordinal == latest_ordinal)
                        .collect::<Vec<_>>();
                    if effective.len() != 1 {
                        return Err(format!(
                            "legacy effective {} carrier must have one block; found {}",
                            spec.marker.name,
                            effective.len()
                        ));
                    }
                    effective.into_iter().next().ok_or_else(|| {
                        format!("effective {} marker disappeared", spec.marker.name)
                    })?
                }
                SqlCutoffProfile::BaselineV02 => {
                    if occurrences.len() != 1 {
                        return Err(format!(
                            "baseline physical {} occurrence count must be one; found {}",
                            spec.marker.name,
                            occurrences.len()
                        ));
                    }
                    occurrences.into_iter().next().ok_or_else(|| {
                        format!("baseline {} marker disappeared", spec.marker.name)
                    })?
                }
            };

        let definition = latest_definition(migrations, spec.owner_identity)?;
        if definition.path != marker.path {
            return Err(format!(
                "{} effective marker carrier {} differs from latest owner {} carrier {}",
                spec.marker.name,
                marker.path.display(),
                spec.owner_identity,
                definition.path.display()
            ));
        }
        let body_range = &definition.dollar_quoted_body.body_range;
        if marker.block_range.start < body_range.start || marker.block_range.end > body_range.end {
            return Err(format!(
                "{} marker block {:?} is not fully contained in latest owner {} body {:?} in {}",
                spec.marker.name,
                marker.block_range,
                spec.owner_identity,
                body_range,
                marker.path.display()
            ));
        }
        inventory.push(GuardInventoryEntry {
            marker_family: spec.marker.name,
            owner_identity: spec.owner_identity,
            carrier: marker.path,
        });
    }

    if inventory.len() != 9
        || inventory
            .iter()
            .map(|entry| entry.owner_identity)
            .collect::<BTreeSet<_>>()
            .len()
            != 8
    {
        return Err("validated inventory did not retain 9 marker families / 8 guards".to_owned());
    }
    Ok(inventory)
}
