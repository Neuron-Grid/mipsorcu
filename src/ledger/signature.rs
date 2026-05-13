use std::fmt;
use std::num::NonZeroU32;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::canonical::LedgerCanonicalPayload;
use super::constants::{
    LEDGER_ED25519_PUBLIC_KEY_LENGTH, LEDGER_ED25519_SECRET_KEY_LENGTH, LEDGER_SIGNATURE_LENGTH,
};
use super::error::LedgerError;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LedgerSignature([u8; LEDGER_SIGNATURE_LENGTH]);

impl LedgerSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() != LEDGER_SIGNATURE_LENGTH {
            return Err(LedgerError::InvalidSignatureLength {
                actual: bytes.len(),
            });
        }

        let mut signature = [0u8; LEDGER_SIGNATURE_LENGTH];
        signature.copy_from_slice(bytes);

        Ok(Self(signature))
    }

    pub fn from_bytea_hex(value: &str) -> Result<Self, LedgerError> {
        let hex_value = value
            .strip_prefix("\\x")
            .ok_or(LedgerError::InvalidSignatureEncoding)?;
        let bytes = hex::decode(hex_value).map_err(|_| LedgerError::InvalidSignatureEncoding)?;

        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; LEDGER_SIGNATURE_LENGTH] {
        &self.0
    }

    pub fn to_bytea_hex(self) -> String {
        format!("\\x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for LedgerSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerSignature")
            .field("len", &LEDGER_SIGNATURE_LENGTH)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerSignatureKeyVersion(NonZeroU32);

impl LedgerSignatureKeyVersion {
    pub fn new(value: u32) -> Result<Self, LedgerError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(LedgerError::InvalidPositiveInteger {
                field: "signature_key_version",
            })
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone)]
pub struct LedgerSigningKey {
    key_version: LedgerSignatureKeyVersion,
    signing_key: SigningKey,
}

impl LedgerSigningKey {
    pub fn from_secret_key_bytes(
        key_version: LedgerSignatureKeyVersion,
        secret_key: &[u8],
    ) -> Result<Self, LedgerError> {
        if secret_key.len() != LEDGER_ED25519_SECRET_KEY_LENGTH {
            return Err(LedgerError::InvalidSigningKeyLength {
                actual: secret_key.len(),
            });
        }

        let mut bytes = [0u8; LEDGER_ED25519_SECRET_KEY_LENGTH];
        bytes.copy_from_slice(secret_key);
        let signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();

        Ok(Self {
            key_version,
            signing_key,
        })
    }

    pub fn key_version(&self) -> LedgerSignatureKeyVersion {
        self.key_version
    }

    pub fn verification_key(&self) -> LedgerVerifyingKey {
        LedgerVerifyingKey {
            key_version: self.key_version,
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    pub(super) fn sign_payload(
        &self,
        expected_key_version: LedgerSignatureKeyVersion,
        payload: &LedgerCanonicalPayload,
    ) -> Result<LedgerSignature, LedgerError> {
        if self.key_version != expected_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: expected_key_version.get(),
                actual: self.key_version.get(),
            });
        }

        let signature: Signature = self.signing_key.sign(payload.as_bytes());
        LedgerSignature::from_bytes(&signature.to_bytes())
    }

    /// digest canonical form（UTF-8 バイト列）に対して Ed25519 署名を生成する。
    ///
    /// ADR 0037 §5 に従い、Phase 1 の `LedgerSigningKey` を再利用して
    /// digest canonical bytes に署名する。ledger entry canonical payload とは
    /// 別の署名対象であることに注意。
    pub fn sign_raw_bytes(
        &self,
        expected_key_version: LedgerSignatureKeyVersion,
        bytes: &[u8],
    ) -> Result<LedgerSignature, LedgerError> {
        if self.key_version != expected_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: expected_key_version.get(),
                actual: self.key_version.get(),
            });
        }

        let signature: Signature = self.signing_key.sign(bytes);
        LedgerSignature::from_bytes(&signature.to_bytes())
    }
}

impl fmt::Debug for LedgerSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerSigningKey")
            .field("key_version", &self.key_version)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct LedgerVerifyingKey {
    key_version: LedgerSignatureKeyVersion,
    verifying_key: VerifyingKey,
}

impl LedgerVerifyingKey {
    pub fn from_public_key_bytes(
        key_version: LedgerSignatureKeyVersion,
        public_key: &[u8],
    ) -> Result<Self, LedgerError> {
        if public_key.len() != LEDGER_ED25519_PUBLIC_KEY_LENGTH {
            return Err(LedgerError::InvalidVerificationKeyLength {
                actual: public_key.len(),
            });
        }

        let mut bytes = [0u8; LEDGER_ED25519_PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(public_key);
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| LedgerError::InvalidVerificationKey)?;

        Ok(Self {
            key_version,
            verifying_key,
        })
    }

    pub fn key_version(&self) -> LedgerSignatureKeyVersion {
        self.key_version
    }

    pub fn as_bytes(&self) -> [u8; LEDGER_ED25519_PUBLIC_KEY_LENGTH] {
        self.verifying_key.to_bytes()
    }

    pub fn fingerprint_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub(super) fn verify_payload(
        &self,
        expected_key_version: LedgerSignatureKeyVersion,
        payload: &LedgerCanonicalPayload,
        signature: &LedgerSignature,
    ) -> Result<(), LedgerError> {
        if self.key_version != expected_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: expected_key_version.get(),
                actual: self.key_version.get(),
            });
        }

        let signature = Signature::from_bytes(signature.as_bytes());
        self.verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| LedgerError::SignatureInvalid { sequence_no: 0 })
    }

    pub fn verify_digest_bytes(
        &self,
        bytes: &[u8],
        signature: &LedgerSignature,
    ) -> Result<(), LedgerError> {
        let sig = Signature::from_bytes(signature.as_bytes());
        self.verifying_key
            .verify(bytes, &sig)
            .map_err(|_| LedgerError::DigestSignatureInvalid)
    }
}

impl fmt::Debug for LedgerVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerVerifyingKey")
            .field("key_version", &self.key_version)
            .finish()
    }
}

pub type LedgerVerificationKey = LedgerVerifyingKey;
