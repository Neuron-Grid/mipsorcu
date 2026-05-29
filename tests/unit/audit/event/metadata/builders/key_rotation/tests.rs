use super::*;

#[test]
fn key_rotation_start_metadata_builds_expected_keys() {
    let old_kv = KeyVersion::new(1).unwrap();
    let new_kv = KeyVersion::new(2).unwrap();
    let metadata = KeyRotationStartMetadata::new(old_kv, new_kv)
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["old_key_version"], 1);
    assert_eq!(value["new_key_version"], 2);
}

#[test]
fn key_rotation_reencrypt_metadata_builds_expected_keys() {
    let old_kv = KeyVersion::new(1).unwrap();
    let new_kv = KeyVersion::new(2).unwrap();
    let metadata = KeyRotationReencryptMetadata::new(old_kv, new_kv, 100, 50, 50)
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["batch_size"], 100);
    assert_eq!(value["processed_count"], 50);
    assert_eq!(value["remaining_count"], 50);
}

#[test]
fn key_rotation_complete_metadata_builds_expected_keys() {
    let old_kv = KeyVersion::new(1).unwrap();
    let new_kv = KeyVersion::new(2).unwrap();
    let metadata = KeyRotationCompleteMetadata::new(old_kv, new_kv, 0)
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["old_key_version"], 1);
    assert_eq!(value["new_key_version"], 2);
    assert_eq!(value["remaining_count"], 0);
}
