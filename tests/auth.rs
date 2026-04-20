use std::error::Error;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mipsorcu::{
    Jwk, Jwks, JwksCache, JwksFetchError, JwtVerificationError, JwtVerifier, JwtVerifierConfig,
    OwnerUserId, RawJwt,
};
use serde::Serialize;

const KEY_ID: &str = "test-key-1";
const ISSUER: &str = "https://project-ref.supabase.co/auth/v1";
const AUDIENCE: &str = "authenticated";
const SUBJECT_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_KEY_ID: &str = "other-key";
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

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

fn jwks_with_key_id(key_id: &str) -> TestResult<Jwks> {
    Ok(Jwks::new(vec![Jwk::new(
        "RSA",
        key_id,
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        RSA_MODULUS,
        RSA_EXPONENT,
    )])?)
}

fn verifier() -> TestResult<JwtVerifier> {
    Ok(JwtVerifier::new(
        JwtVerifierConfig::new(ISSUER, AUDIENCE)?,
        jwks_with_key_id(KEY_ID)?,
    ))
}

fn claims(sub: &str, iss: &str, aud: &str, exp: u64) -> TestClaims {
    TestClaims {
        sub: sub.to_owned(),
        iss: iss.to_owned(),
        aud: aud.to_owned(),
        exp,
    }
}

fn signed_token_with_key_id(
    key_id: Option<&str>,
    algorithm: Algorithm,
    claims: TestClaims,
) -> TestResult<String> {
    let mut header = Header::new(algorithm);
    header.kid = key_id.map(str::to_owned);
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())?;

    Ok(encode(&header, &claims, &key)?)
}

fn valid_token() -> TestResult<String> {
    signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS256,
        claims(SUBJECT_USER_ID, ISSUER, AUDIENCE, 4_102_444_800),
    )
}

#[test]
fn verifier_accepts_valid_rs256_jwt_from_matching_jwks() -> TestResult<()> {
    let raw_jwt = RawJwt::new(&valid_token()?)?;

    let verified = verifier()?.verify(&raw_jwt)?;

    assert_eq!(
        verified.subject_user_id(),
        &OwnerUserId::parse(SUBJECT_USER_ID)?
    );
    assert_eq!(verified.issuer(), ISSUER);
    assert_eq!(verified.audience(), AUDIENCE);
    assert_eq!(verified.expires_at(), 4_102_444_800);

    Ok(())
}

#[test]
fn raw_jwt_rejects_empty_and_redacts_debug_output() -> TestResult<()> {
    assert!(matches!(
        RawJwt::new(""),
        Err(JwtVerificationError::EmptyToken)
    ));
    assert!(matches!(
        RawJwt::new("   "),
        Err(JwtVerificationError::EmptyToken)
    ));

    let token = valid_token()?;
    let raw_jwt = RawJwt::new(&token)?;
    let debug = format!("{raw_jwt:?}");

    assert!(debug.contains("len"));
    assert!(!debug.contains(&token));

    Ok(())
}

#[test]
fn verifier_rejects_missing_key_id() -> TestResult<()> {
    let token = signed_token_with_key_id(
        None,
        Algorithm::RS256,
        claims(SUBJECT_USER_ID, ISSUER, AUDIENCE, 4_102_444_800),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::MissingKeyId)));

    Ok(())
}

#[test]
fn verifier_rejects_unknown_key_id() -> TestResult<()> {
    let raw_jwt = RawJwt::new(&valid_token()?)?;
    let verifier = JwtVerifier::new(
        JwtVerifierConfig::new(ISSUER, AUDIENCE)?,
        jwks_with_key_id(OTHER_KEY_ID)?,
    );

    let result = verifier.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::KeyNotFound)));

    Ok(())
}

#[test]
fn verifier_rejects_unsupported_algorithm() -> TestResult<()> {
    let token = signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS384,
        claims(SUBJECT_USER_ID, ISSUER, AUDIENCE, 4_102_444_800),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(
        result,
        Err(JwtVerificationError::UnsupportedAlgorithm)
    ));

    Ok(())
}

#[test]
fn verifier_rejects_tampered_signature() -> TestResult<()> {
    let token = valid_token()?;
    let mut segments = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    if segments.len() != 3 {
        return Err(JwtVerificationError::InvalidToken.into());
    }
    let first = segments[2]
        .get(0..1)
        .ok_or(JwtVerificationError::InvalidToken)?;
    let replacement = if first == "A" { "B" } else { "A" };
    segments[2].replace_range(0..1, replacement);
    let token = segments.join(".");
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(
        result,
        Err(JwtVerificationError::InvalidSignature)
    ));

    Ok(())
}

#[test]
fn verifier_rejects_expired_token() -> TestResult<()> {
    let token = signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS256,
        claims(SUBJECT_USER_ID, ISSUER, AUDIENCE, 1),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::Expired)));

    Ok(())
}

#[test]
fn verifier_rejects_invalid_issuer() -> TestResult<()> {
    let token = signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS256,
        claims(
            SUBJECT_USER_ID,
            "https://other-project.supabase.co/auth/v1",
            AUDIENCE,
            4_102_444_800,
        ),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::InvalidIssuer)));

    Ok(())
}

#[test]
fn verifier_rejects_invalid_audience() -> TestResult<()> {
    let token = signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS256,
        claims(SUBJECT_USER_ID, ISSUER, "anon", 4_102_444_800),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::InvalidAudience)));

    Ok(())
}

#[test]
fn verifier_rejects_invalid_subject() -> TestResult<()> {
    let token = signed_token_with_key_id(
        Some(KEY_ID),
        Algorithm::RS256,
        claims("not-a-uuid", ISSUER, AUDIENCE, 4_102_444_800),
    )?;
    let raw_jwt = RawJwt::new(&token)?;

    let result = verifier()?.verify(&raw_jwt);

    assert!(matches!(result, Err(JwtVerificationError::InvalidSubject)));

    Ok(())
}

#[test]
fn verifier_uses_updated_jwks_cache() -> TestResult<()> {
    let cache = JwksCache::new(jwks_with_key_id(KEY_ID)?);
    let verifier =
        JwtVerifier::with_cache(JwtVerifierConfig::new(ISSUER, AUDIENCE)?, cache.clone());
    let new_key_token = signed_token_with_key_id(
        Some(OTHER_KEY_ID),
        Algorithm::RS256,
        claims(SUBJECT_USER_ID, ISSUER, AUDIENCE, 4_102_444_800),
    )?;
    let raw_jwt = RawJwt::new(&new_key_token)?;

    let before_update = verifier.verify(&raw_jwt);
    assert!(matches!(
        before_update,
        Err(JwtVerificationError::KeyNotFound)
    ));

    cache.replace(jwks_with_key_id(OTHER_KEY_ID)?)?;
    let verified = verifier.verify(&raw_jwt)?;

    assert_eq!(
        verified.subject_user_id(),
        &OwnerUserId::parse(SUBJECT_USER_ID)?
    );

    Ok(())
}

#[test]
fn jwks_new_rejects_empty_and_invalid_keys() -> TestResult<()> {
    assert!(matches!(
        Jwks::new(Vec::new()),
        Err(JwtVerificationError::InvalidJwks)
    ));

    let invalid_key = Jwk::new(
        "oct",
        KEY_ID,
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        RSA_MODULUS,
        RSA_EXPONENT,
    );

    assert!(matches!(
        Jwks::new(vec![invalid_key]),
        Err(JwtVerificationError::InvalidJwks)
    ));

    let invalid_algorithm = Jwk::new(
        "RSA",
        KEY_ID,
        Some("RS384".to_owned()),
        Some("sig".to_owned()),
        RSA_MODULUS,
        RSA_EXPONENT,
    );

    assert!(matches!(
        Jwks::new(vec![invalid_algorithm]),
        Err(JwtVerificationError::UnsupportedAlgorithm)
    ));

    Ok(())
}

#[test]
fn jwks_fetch_error_display_does_not_expose_response_body() {
    let error = JwksFetchError::NonSuccessStatus { status: 500 };
    let rendered = error.to_string();

    assert!(rendered.contains("status 500"));
    assert!(!rendered.contains("upstream secret"));
}
