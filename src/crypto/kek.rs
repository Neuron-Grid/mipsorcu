pub mod envvar;

pub use crate::error::KekError;
pub use envvar::EnvVarKek;

use crate::types::{DekPlaintext, KekAlgorithm, KekVersion, WrappedDek};

pub trait KekProvider: Send + Sync {
    fn wrap_dek(&self, dek: &DekPlaintext) -> Result<WrappedDek, KekError>;
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<DekPlaintext, KekError>;
    fn kek_version(&self) -> KekVersion;
    fn kek_algorithm(&self) -> KekAlgorithm;
}
