use std::io;

use mipsorcu::{
    AadV1, Ciphertext, CryptoError, EncryptedDataKey, EnvVarKek, KekAlgorithm, KekVersion,
    KeyVersion, MASTER_KEY_LENGTH, MasterKey, MasterKeyRing, Nonce, Plaintext, SecretDecryptError,
    SecretId, SecretVersionRecord, WrappedDek, open_dispatched, open_legacy_v01, open_v02,
};
use serde::Deserialize;
use serde_json::Value;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const V01_FIXTURE_JSON: &str = include_str!("fixtures/v01_envelope/expected.json");
const V02_FIXTURE_JSON: &str = include_str!("fixtures/v02_envelope/expected.json");
const V01_MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [11u8; MASTER_KEY_LENGTH];
const V02_MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [12u8; MASTER_KEY_LENGTH];

#[derive(Debug, Deserialize)]
struct EnvelopeFixture {
    format: String,
    secret_id: String,
    owner_user_id: String,
    classification: String,
    created_at: String,
    version: u32,
    key_version: u32,
    kek_version: Option<u32>,
    plaintext_utf8: String,
    ciphertext_hex: String,
    nonce_hex: String,
    encrypted_data_key_hex: Option<String>,
    wrapped_dek_hex: Option<String>,
    dek_wrap_algorithm: Option<String>,
    aad_context: Value,
}

fn fixture_v01() -> TestResult<EnvelopeFixture> {
    Ok(serde_json::from_str(V01_FIXTURE_JSON)?)
}

fn fixture_v02() -> TestResult<EnvelopeFixture> {
    Ok(serde_json::from_str(V02_FIXTURE_JSON)?)
}

fn missing_field(field: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("missing fixture field {field}"),
    )
}

fn decode_hex(value: &str) -> TestResult<Vec<u8>> {
    Ok(hex::decode(value)?)
}

fn fixture_aad(fixture: &EnvelopeFixture) -> TestResult<AadV1> {
    let stored_aad = AadV1::from_stored_context(&fixture.aad_context)?;
    let row_aad = AadV1::parse(
        &fixture.secret_id,
        fixture.version,
        &fixture.owner_user_id,
        &fixture.classification,
        &fixture.created_at,
    )?;

    assert_eq!(stored_aad.canonical_bytes()?, row_aad.canonical_bytes()?);

    Ok(stored_aad)
}

fn legacy_keyring() -> TestResult<MasterKeyRing> {
    Ok(MasterKeyRing::single(
        KeyVersion::new(1)?,
        MasterKey::from_bytes(V01_MASTER_KEY_BYTES),
    )?)
}

fn dual_path_keyring() -> TestResult<MasterKeyRing> {
    Ok(MasterKeyRing::from_key_entries(
        KeyVersion::new(2)?,
        [
            (
                KeyVersion::new(1)?,
                MasterKey::from_bytes(V01_MASTER_KEY_BYTES),
            ),
            (
                KeyVersion::new(2)?,
                MasterKey::from_bytes(V02_MASTER_KEY_BYTES),
            ),
        ],
    )?)
}

fn v02_kek() -> TestResult<EnvVarKek> {
    Ok(EnvVarKek::single(
        KekVersion::new(2)?,
        MasterKey::from_bytes(V02_MASTER_KEY_BYTES),
    )?)
}

fn legacy_record(fixture: &EnvelopeFixture) -> TestResult<SecretVersionRecord> {
    assert_eq!(fixture.format, "v01");
    Ok(SecretVersionRecord {
        secret_id: SecretId::parse(&fixture.secret_id)?,
        key_version: KeyVersion::new(fixture.key_version)?,
        ciphertext: Ciphertext::new(decode_hex(&fixture.ciphertext_hex)?)?,
        nonce: Nonce::parse(&decode_hex(&fixture.nonce_hex)?)?,
        encrypted_data_key: Some(EncryptedDataKey::parse(&decode_hex(
            fixture
                .encrypted_data_key_hex
                .as_deref()
                .ok_or_else(|| missing_field("encrypted_data_key_hex"))?,
        )?)?),
        wrapped_dek: None,
        dek_wrap_algorithm: None,
    })
}

fn v02_parts(fixture: &EnvelopeFixture) -> TestResult<(Ciphertext, Nonce, WrappedDek, AadV1)> {
    assert_eq!(fixture.format, "v02");
    assert_eq!(
        fixture
            .dek_wrap_algorithm
            .as_deref()
            .map(KekAlgorithm::parse)
            .transpose()?,
        Some(KekAlgorithm::EnvvarXchachaV2)
    );
    let kek_version = KekVersion::new(
        fixture
            .kek_version
            .ok_or_else(|| missing_field("kek_version"))?,
    )?;
    Ok((
        Ciphertext::new(decode_hex(&fixture.ciphertext_hex)?)?,
        Nonce::parse(&decode_hex(&fixture.nonce_hex)?)?,
        WrappedDek::parse(
            kek_version,
            &decode_hex(
                fixture
                    .wrapped_dek_hex
                    .as_deref()
                    .ok_or_else(|| missing_field("wrapped_dek_hex"))?,
            )?,
        )?,
        fixture_aad(fixture)?,
    ))
}

fn v02_record(fixture: &EnvelopeFixture) -> TestResult<SecretVersionRecord> {
    let (ciphertext, nonce, wrapped_dek, _) = v02_parts(fixture)?;
    Ok(SecretVersionRecord {
        secret_id: SecretId::parse(&fixture.secret_id)?,
        key_version: KeyVersion::new(fixture.key_version)?,
        ciphertext,
        nonce,
        encrypted_data_key: None,
        wrapped_dek: Some(wrapped_dek),
        dek_wrap_algorithm: Some(KekAlgorithm::EnvvarXchachaV2),
    })
}

fn tamper_first_byte(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut tampered = bytes.to_vec();
    let byte = tampered
        .first_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty tamper target"))?;
    *byte ^= 1;

    Ok(tampered)
}

fn tamper_last_byte(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut tampered = bytes.to_vec();
    let byte = tampered
        .last_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty tamper target"))?;
    *byte ^= 1;

    Ok(tampered)
}

fn assert_decryption_failed(result: Result<Plaintext, SecretDecryptError>) {
    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(CryptoError::DecryptionFailed))
    ));
}

fn assert_key_unwrap_failed(result: Result<Plaintext, SecretDecryptError>) {
    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(CryptoError::KeyUnwrapFailed))
    ));
}

#[test]
fn p1_same_plaintext_and_aad_decrypts_equivalently_across_formats() -> TestResult<()> {
    let v01 = fixture_v01()?;
    let v02 = fixture_v02()?;
    let keyring = dual_path_keyring()?;
    let v01_aad = fixture_aad(&v01)?;
    let v02_aad = fixture_aad(&v02)?;

    let legacy_plaintext = open_dispatched(&keyring, &legacy_record(&v01)?, &v01_aad)?;
    let envelope_plaintext = open_dispatched(&keyring, &v02_record(&v02)?, &v02_aad)?;

    assert_eq!(v01.plaintext_utf8, v02.plaintext_utf8);
    assert_eq!(v01_aad.canonical_bytes()?, v02_aad.canonical_bytes()?);
    assert_eq!(legacy_plaintext.as_bytes(), envelope_plaintext.as_bytes());

    Ok(())
}

#[test]
fn p2_v01_fixture_decrypts_to_fixed_plaintext() -> TestResult<()> {
    let fixture = fixture_v01()?;
    let plaintext = open_legacy_v01(
        &legacy_keyring()?,
        &legacy_record(&fixture)?,
        &fixture_aad(&fixture)?,
    )?;

    assert_eq!(plaintext.as_bytes(), fixture.plaintext_utf8.as_bytes());

    Ok(())
}

#[test]
fn p3_v02_fixture_decrypts_to_fixed_plaintext() -> TestResult<()> {
    let fixture = fixture_v02()?;
    let (ciphertext, nonce, wrapped_dek, aad) = v02_parts(&fixture)?;
    let direct = open_v02(&v02_kek()?, &wrapped_dek, &ciphertext, &nonce, &aad)?;
    let dispatched = open_dispatched(&dual_path_keyring()?, &v02_record(&fixture)?, &aad)?;

    assert_eq!(direct.as_bytes(), fixture.plaintext_utf8.as_bytes());
    assert_eq!(dispatched.as_bytes(), fixture.plaintext_utf8.as_bytes());

    Ok(())
}

#[test]
fn p4_aad_tampering_fails_both_formats() -> TestResult<()> {
    let v01 = fixture_v01()?;
    let v02 = fixture_v02()?;
    let wrong_aad = AadV1::parse(
        &v01.secret_id,
        v01.version + 1,
        &v01.owner_user_id,
        &v01.classification,
        &v01.created_at,
    )?;
    let (ciphertext, nonce, wrapped_dek, _) = v02_parts(&v02)?;

    assert_decryption_failed(open_legacy_v01(
        &legacy_keyring()?,
        &legacy_record(&v01)?,
        &wrong_aad,
    ));
    assert_decryption_failed(open_v02(
        &v02_kek()?,
        &wrapped_dek,
        &ciphertext,
        &nonce,
        &wrong_aad,
    ));

    Ok(())
}

#[test]
fn p5_nonce_tampering_fails_both_formats() -> TestResult<()> {
    let v01 = fixture_v01()?;
    let v02 = fixture_v02()?;
    let aad_v01 = fixture_aad(&v01)?;
    let aad_v02 = fixture_aad(&v02)?;
    let mut legacy = legacy_record(&v01)?;
    legacy.nonce = Nonce::parse(&tamper_first_byte(legacy.nonce.as_bytes())?)?;
    let (ciphertext, nonce, wrapped_dek, _) = v02_parts(&v02)?;
    let tampered_nonce = Nonce::parse(&tamper_first_byte(nonce.as_bytes())?)?;

    assert_decryption_failed(open_legacy_v01(&legacy_keyring()?, &legacy, &aad_v01));
    assert_decryption_failed(open_v02(
        &v02_kek()?,
        &wrapped_dek,
        &ciphertext,
        &tampered_nonce,
        &aad_v02,
    ));

    Ok(())
}

#[test]
fn p6_ciphertext_bit_tampering_fails_both_formats() -> TestResult<()> {
    let v01 = fixture_v01()?;
    let v02 = fixture_v02()?;
    let aad_v01 = fixture_aad(&v01)?;
    let aad_v02 = fixture_aad(&v02)?;
    let mut legacy = legacy_record(&v01)?;
    legacy.ciphertext = Ciphertext::new(tamper_first_byte(legacy.ciphertext.as_bytes())?)?;
    let (ciphertext, nonce, wrapped_dek, _) = v02_parts(&v02)?;
    let tampered_ciphertext = Ciphertext::new(tamper_first_byte(ciphertext.as_bytes())?)?;

    assert_decryption_failed(open_legacy_v01(&legacy_keyring()?, &legacy, &aad_v01));
    assert_decryption_failed(open_v02(
        &v02_kek()?,
        &wrapped_dek,
        &tampered_ciphertext,
        &nonce,
        &aad_v02,
    ));

    Ok(())
}

#[test]
fn p7_v02_wrapped_dek_tampering_fails_closed() -> TestResult<()> {
    let fixture = fixture_v02()?;
    let (ciphertext, nonce, wrapped_dek, aad) = v02_parts(&fixture)?;
    let tampered_wrapped_dek = WrappedDek::parse(
        wrapped_dek.kek_version(),
        &tamper_last_byte(wrapped_dek.as_bytes())?,
    )?;

    assert_key_unwrap_failed(open_v02(
        &v02_kek()?,
        &tampered_wrapped_dek,
        &ciphertext,
        &nonce,
        &aad,
    ));

    Ok(())
}

#[test]
fn p8_v01_encrypted_data_key_tampering_fails_closed() -> TestResult<()> {
    let fixture = fixture_v01()?;
    let mut record = legacy_record(&fixture)?;
    let encrypted_data_key = record
        .encrypted_data_key
        .as_ref()
        .ok_or_else(|| missing_field("encrypted_data_key"))?;
    record.encrypted_data_key = Some(EncryptedDataKey::parse(&tamper_last_byte(
        encrypted_data_key.as_bytes(),
    )?)?);

    assert_key_unwrap_failed(open_legacy_v01(
        &legacy_keyring()?,
        &record,
        &fixture_aad(&fixture)?,
    ));

    Ok(())
}

#[test]
fn p9_unknown_dek_wrap_algorithm_fails_closed() {
    assert!(matches!(
        KekAlgorithm::parse("envvar-xchacha-v3"),
        Err(CryptoError::UnknownDekWrapAlgorithm)
    ));
}
