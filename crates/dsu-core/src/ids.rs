//! Validated names and identifiers used across the API, the state files and the config.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value that does not have the shape its type requires.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind} {value:?} is not valid: {rule}")]
pub struct InvalidId {
    /// What was being parsed (`service name`, `deploy id`, `digest`).
    pub kind: &'static str,
    /// The refused input.
    pub value: String,
    /// The rule it breaks.
    pub rule: &'static str,
}

macro_rules! string_newtype {
    ($(#[$m:meta])* $name:ident, $kind:literal, $check:path) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Parses and validates `value`.
            pub fn parse(value: &str) -> Result<Self, InvalidId> {
                match $check(value) {
                    Ok(()) => Ok(Self(value.to_owned())),
                    Err(rule) => Err(InvalidId { kind: $kind, value: value.to_owned(), rule }),
                }
            }

            /// The validated text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = String::deserialize(d)?;
                Self::parse(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn check_service(v: &str) -> Result<(), &'static str> {
    let ok_len = (1..=63).contains(&v.len());
    let ok_chars = v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok_len && ok_chars { Ok(()) } else { Err("[a-z0-9-]{1,63}") }
}

fn check_deploy_id(v: &str) -> Result<(), &'static str> {
    let body = v.strip_prefix("d-").unwrap_or("");
    let ok = body.len() == 26 && body.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    if ok { Ok(()) } else { Err("d-[a-z2-7]{26}") }
}

fn check_digest(v: &str) -> Result<(), &'static str> {
    let hex = v.strip_prefix("sha256:").unwrap_or("");
    let ok = hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok { Ok(()) } else { Err("sha256:[0-9a-f]{64}") }
}

string_newtype!(
    /// A configured service name: the `{service}` of the API, `[a-z0-9-]{1,63}`.
    ServiceName, "service name", check_service
);
string_newtype!(
    /// A deploy record id, `d-[a-z2-7]{26}` (128 random bits in base32).
    DeployId, "deploy id", check_deploy_id
);
string_newtype!(
    /// A SHA-256 content digest, `sha256:[0-9a-f]{64}`.
    Digest, "digest", check_digest
);

impl Digest {
    /// The 64 lower-case hex digits after `sha256:`.
    pub fn hex(&self) -> &str {
        &self.0["sha256:".len()..]
    }

    /// The digest of 32 raw SHA-256 bytes.
    pub fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(format!("sha256:{}", hex::encode(bytes)))
    }
}

impl DeployId {
    /// Builds an id from 16 random bytes: `d-` and 26 base32 (RFC 4648, lower case,
    /// unpadded) characters.
    pub fn from_random(bytes: [u8; 16]) -> Self {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut out = String::from("d-");
        let mut acc: u32 = 0;
        let mut bits = 0;
        for b in bytes {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
            }
        }
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
        Self(out)
    }
}
