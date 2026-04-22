use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mipsorcu::{
    AuthorizationError, Jwk, Jwks, JwtVerifier, JwtVerifierConfig, OwnerUserId, RawJwt,
    VerifiedJwtClaims, authorize_existing_secret_version_write, authorize_new_secret_create,
};
use serde::Serialize;

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
const KEY_ID: &str = "test-key-1";
const ISSUER: &str = "https://project-ref.supabase.co/auth/v1";
const AUDIENCE: &str = "authenticated";
const RSA_MODULUS: &str = "0cOAzuft7zMhmD42QSngblYMsfhQD5IqUDK2S8sZw_TM0tNaPvMj-JqyM1bx4PaWDDjX018m8ys7wmOFSyfrl0TpWFzFMwUxLzsTgM1izd_a_Kk1IBRUREuYuAHr1TDZOoXqGncTC6xb-Jd4n58zjxsB3wO3OFBn_qP_Wsv4oPhiqLcya1UdyXEO905iIkigCdDa7VT7T6ogTrR-RGqZHON05UYXCmqSfAUBTy6dHowjQio0eHLUYAhDTv5q7oIcvb_SHbL-W-Q6GqsdFlQXJMXydSsTqBwlxs_7fSbOPqGfTxUeEzN5kyH1kn78oRK-toDT-ASKyu3Uh9sMV7fdqw";
const RSA_EXPONENT: &str = "AQAB";
const RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRw4DO5+3vMyGY
PjZBKeBuVgyx+FAPkipQMrZLyxnD9MzS01o+8yP4mrIzVvHg9pYMONfTXybzKzvC
Y4VLJ+uXROlYXMUzBTEvOxOAzWLN39r8qTUgFFRES5i4AevVMNk6heoadxMLrFv4
l3ifnzOPGwHfA7c4UGf+o/9ay/ig+GKotzJrVR3JcQ73TmIiSKAJ0NrtVPtPqiBO
tH5Eapkc43TlRhcKapJ8BQFPLp0ejCNCKjR4ctRgCENO/mrughy9v9Idsv5b5Doa
qx0WVBckxfJ1KxOoHCXGz/t9Js4+oZ9PFR4TM3mTIfWSfvyhEr62gNP4BIrK7dSH
2wxXt92rAgMBAAECggEAAewnItm/dZRomg5ixDH7Rc52Oy55yDmbyc/y4sPx+d1J
25EUdt/yT4XEAaAFcQ+YWgcJ6aFgsV2ztrkooqd8XcWfRQJop2pEaOsMecg6ZIVb
WF9SD660liY5OE8UxSw3gpnfKy5/MrBno6tDuNI4oq2gndWP9IisHsFDBqcUD1dQ
5wUILJiQwI4wW0Bm5MHkzMjuSx0W5ZwkRjfc8EI17mbmBYQD56l6NJsiPatvYn2T
dFeW/jtPhnX8xXslxIDlKgdT/HODUE/azNJKw8vzDWjTAbSejuEJriZXcQxvtZfN
YY6P9Au5IQsjamJdas75PzF6XhT6QODatnxVV7ySPQKBgQDpSxX8wVwF/qHFk0YM
59ACc71kOkkkaT2Hc1fCoZPYbgYR4seO2cOkkRpiFoi5HrA5lNEoQBJJIJvtoL/4
cLSFIWRqGNtvH/NDoGEeF7GSn2i0LCb2jX5vuiY3bSlEj2JHiFTwizsmwhydokQM
jFKzDBJ+snk6gddUx1DgKaMMVwKBgQDmLiKiSwI615c3fCAEXP5UakK9VwjpkYAp
KIIz/RIokcW7+NP1xbFtj/06M7O4IasLOvugMPDzN/WJQ/gzA1m+bajwl22f7lRn
l4GMnFztVmGptTg+EzU0GORkRd3boEtwpd2FZ/WhfaTLP8BGIcvNu7frdGbpkcWK
iVNqtjNkzQKBgD9FO+tWzYxaqKka7g6l+AYSObUrEZcsa6GGqLCCfcRe4oqLRK/7
Y1IIgG1Fy0LZjdWwBKGz7sGidGeYBzhr6KmKit8zap/SvHkE0BIHPwOS9CSZLOAF
M9s9UwwJMP4FHRRlZxPtztcOIhCmZ2o3zF3+0i1GXhZ+DFZT0B1bbXr1AoGBANC5
XSaVpfv9q13g7JeITAf4I3TWC3rhOboYxZinD2RCa2+8f1gKYI3dV98DKyD5RsT0
Q2BLgPLL95b1T4fSrfqELgGdDwdLcrZNKGh9EbcV8ZGWht2jRUdsmw5iXH/fpwkL
Hwjt8Er0SA8WTCBMXSa95lVYREngqaSqSj4l4gyxAoGBAMf4zUq0pOLJA2rk9k7f
P7LJUPgASNpxGsG/FBDE+rTQl1tqVgHsI20KULCrQ5a2ob4sGlGfF8p2M5s5dcoM
fgr74PXMRn15mEnR/ieIFJEIIKAqG+eJE8E4wtXf8L3swtrg1s2mYe3km/Ly0gNH
o6OiVJrW2fR4F3HzG53Td7eh
-----END PRIVATE KEY-----"#;

#[derive(Clone, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

fn claims_for(user_id: &str) -> VerifiedJwtClaims {
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())
        .expect("test private key should parse");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_owned());
    let token = encode(
        &header,
        &TestClaims {
            sub: user_id.to_owned(),
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            exp: 4_102_444_800,
        },
        &key,
    )
    .expect("test jwt should encode");
    let raw_jwt = RawJwt::new(&token).expect("test jwt should parse");
    let verifier = JwtVerifier::new(
        JwtVerifierConfig::new(ISSUER, AUDIENCE).expect("test verifier config should parse"),
        Jwks::new(vec![Jwk::new(
            "RSA",
            KEY_ID,
            Some("RS256".to_owned()),
            Some("sig".to_owned()),
            RSA_MODULUS,
            RSA_EXPONENT,
        )])
        .expect("test jwks should parse"),
    );

    verifier.verify(&raw_jwt).expect("test jwt should verify")
}

#[test]
fn existing_secret_version_write_allows_owner() {
    let owner_user_id = OwnerUserId::parse(OWNER_USER_ID).expect("owner id should parse");

    let result =
        authorize_existing_secret_version_write(&claims_for(OWNER_USER_ID), &owner_user_id);

    assert!(result.is_ok());
}

#[test]
fn new_secret_create_allows_verified_user() {
    let result = authorize_new_secret_create(&claims_for(OWNER_USER_ID));

    assert!(result.is_ok());
}

#[test]
fn existing_secret_version_write_rejects_non_owner() {
    let owner_user_id = OwnerUserId::parse(OWNER_USER_ID).expect("owner id should parse");

    let result =
        authorize_existing_secret_version_write(&claims_for(OTHER_USER_ID), &owner_user_id);

    assert!(matches!(result, Err(AuthorizationError::OwnerMismatch)));
}
