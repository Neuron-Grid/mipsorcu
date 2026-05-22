pub const LEDGER_CANONICALIZATION_VERSION_V1: u8 = 1;
pub const LEDGER_CANONICAL_SCHEMA_V1: &str = "mipsorcu.ledger_entry.v1";
pub const LEDGER_HASH_ALGORITHM_SHA256: &str = "sha-256";
pub const LEDGER_SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
pub const LEDGER_HASH_LENGTH: usize = 32;
pub const LEDGER_SIGNATURE_LENGTH: usize = 64;
pub const LEDGER_ED25519_SECRET_KEY_LENGTH: usize = 32;
pub const LEDGER_ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const LEDGER_PAYLOAD_MAX_CANONICAL_BYTES: usize = 8192;

pub(super) const LEDGER_I64_MAX_U64: u64 = 9_223_372_036_854_775_807;

pub const FORBIDDEN_LEDGER_PAYLOAD_KEYS: &[&str] = &[
    "alias_decryption_key",
    "alias_encryption_key",
    "alias_fingerprint_key",
    "authorization",
    "authorization_header",
    "bearer_token",
    "canonical_alias_plaintext",
    "ciphertext",
    "data_key",
    "decrypt_result",
    "decrypted",
    "decrypted_data",
    "ed25519_private_key",
    "encrypted_data_key",
    "jwt",
    "jwt_full",
    "ledger_signing_key",
    "master_key",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "request_body_full",
    "response_body",
    "response_body_full",
    "secret_body",
    "secret_key",
    "secret_value",
    "service_role",
    "service_role_key",
    "token",
];
