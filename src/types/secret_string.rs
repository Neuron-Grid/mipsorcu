//! 外部 backend 認証用の秘密文字列ラッパ型。
//!
//! Token / API key / shared secret などの「文字列で授受されるが Display や
//! Debug で出力してはならない素材」を扱うための共通型。`Drop` 時に内部バッファを
//! zeroize し、`Debug` は固定の伏字を返し、`Display` / `serde::Serialize` を
//! 実装しないことで型レベルでログ・JSON 経由の漏洩を防ぐ。
//!
//! 信頼境界ノート: `as_bytes()` / `expose_secret()` はバックエンドへの I/O
//! 直前にのみ呼び出すこと。文字列を `String` や `&str` へ転写すると伏字保護が
//! 効かなくなる。

use std::fmt;

use zeroize::Zeroize;

/// 秘密文字列を保持する不透明ラッパ。
///
/// 構築後は所有権を持って zeroize する。`Clone` は許容するが、`Debug` で
/// 値を出力しない。`Display` / `serde::Serialize` を実装しないため log や
/// JSON へ素のまま出力できない。
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Vec<u8>);

impl SecretString {
    /// UTF-8 文字列から新規構築する。
    ///
    /// 空文字列は明示的に拒否する。null byte を含む場合も拒否する（HTTP header に
    /// 載せるとプロトコル違反になるため）。
    pub fn new(value: impl AsRef<str>) -> Result<Self, SecretStringError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(SecretStringError::Empty);
        }
        if value.as_bytes().contains(&0) {
            return Err(SecretStringError::ContainsNullByte);
        }
        Ok(Self(value.as_bytes().to_vec()))
    }

    /// 内部バイト列を借用する。バックエンド I/O 直前にだけ使用する。
    pub fn expose_secret(&self) -> &str {
        // SecretString::new は UTF-8 入力のみを受け付けるため unwrap_or は要らない。
        std::str::from_utf8(&self.0).unwrap_or("")
    }

    /// 内部バイト列を生バイトで借用する。HMAC 鍵などのバイナリ取り回し用。
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// 内部バッファのバイト長を返す。`Display` 漏洩を起こさないメトリクス値。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 空かどうか。`new` で空を弾いているため常に false だが API 完全性のため提供。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 内部バッファを直ちに zeroize する。テストおよび手動 zeroize 用。
    pub fn zeroize_in_place(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretString")
            .field("len", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `SecretString` 構築失敗の理由。`Display` には秘密情報を露出しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStringError {
    Empty,
    ContainsNullByte,
}

impl fmt::Display for SecretStringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("secret string must not be empty"),
            Self::ContainsNullByte => formatter.write_str("secret string must not contain NUL"),
        }
    }
}

impl std::error::Error for SecretStringError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_non_empty_ascii() {
        let secret = SecretString::new("hello").expect("non-empty ascii must succeed");
        assert_eq!(secret.expose_secret(), "hello");
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
    }

    #[test]
    fn new_rejects_empty() {
        assert_eq!(SecretString::new(""), Err(SecretStringError::Empty));
    }

    #[test]
    fn new_rejects_null_byte() {
        let value = "abc\0def";
        assert_eq!(
            SecretString::new(value),
            Err(SecretStringError::ContainsNullByte)
        );
    }

    #[test]
    fn debug_does_not_leak_value() {
        let secret = SecretString::new("super-secret-token").expect("ok");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret-token"));
    }

    #[test]
    fn zeroize_in_place_clears_internal_buffer_without_unsafe_observation() {
        let mut secret = SecretString::new("temporary-token").expect("ok");
        secret.zeroize_in_place();
        assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
    }
}
