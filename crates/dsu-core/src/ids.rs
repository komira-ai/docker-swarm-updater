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
    let ok_chars = v
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err("[a-z0-9-]{1,63}")
    }
}

fn check_deploy_id(v: &str) -> Result<(), &'static str> {
    let body = v.strip_prefix("d-").unwrap_or("");
    let ok = body.len() == 26
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    if ok { Ok(()) } else { Err("d-[a-z2-7]{26}") }
}

fn check_digest(v: &str) -> Result<(), &'static str> {
    let hex = v.strip_prefix("sha256:").unwrap_or("");
    let ok = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err("sha256:[0-9a-f]{64}")
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn service_names_are_lower_case_dns_like_labels() {
        for ok in ["a", "app", "app-1", "0", &"a".repeat(63)] {
            assert_eq!(ServiceName::parse(ok).unwrap().as_str(), ok);
        }
        for bad in ["", "App", "a_b", "a b", "a/b", "a.b", &"a".repeat(64), "é"] {
            let err = ServiceName::parse(bad).unwrap_err();
            assert_eq!(err.kind, "service name");
            assert_eq!(err.value, bad);
            assert!(err.to_string().contains("service name"));
        }
    }

    #[test]
    fn deploy_ids_are_d_and_26_base32_characters() {
        let ok = "d-abcdefghijklmnopqrstuvwxyz";
        assert_eq!(DeployId::parse(ok).unwrap().to_string(), ok);
        assert!(DeployId::parse("d-23456723456723456723456723").is_ok());
        let bad = [
            "",
            "d-",
            "x-abcdefghijklmnopqrstuvwxyz",
            "abcdefghijklmnopqrstuvwxyz",
            "d-abcdefghijklmnopqrstuvwxy",
            "d-abcdefghijklmnopqrstuvwxyza",
            "d-abcdefghijklmnopqrstuvwxy1",
            "d-abcdefghijklmnopqrstuvwxy8",
            "d-abcdefghijklmnopqrstuvwxyZ",
        ];
        for text in bad {
            let err = DeployId::parse(text).unwrap_err();
            assert_eq!(err.rule, "d-[a-z2-7]{26}", "{text}");
        }
    }

    #[test]
    fn random_bytes_make_valid_ids() {
        let zero = DeployId::from_random([0; 16]);
        assert_eq!(zero.as_str(), format!("d-{}", "a".repeat(26)));
        let ones = DeployId::from_random([0xff; 16]);
        assert_eq!(ones.as_str(), format!("d-{}4", "7".repeat(25)));
        let mixed = DeployId::from_random([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(DeployId::parse(mixed.as_str()).unwrap(), mixed);
        assert_ne!(mixed, zero);
    }

    #[test]
    fn digests_are_sha256_and_64_lower_case_hex() {
        let text = format!("sha256:{HEX64}");
        let d = Digest::parse(&text).unwrap();
        assert_eq!(d.as_str(), text);
        assert_eq!(d.hex(), HEX64);
        let upper = format!("sha256:{}", HEX64.to_uppercase());
        let short = format!("sha256:{}", &HEX64[1..]);
        let long = format!("sha256:{HEX64}0");
        let not_hex = format!("sha256:{}g", &HEX64[1..]);
        let bad = [
            "",
            HEX64,
            "sha512:0123",
            short.as_str(),
            long.as_str(),
            upper.as_str(),
            not_hex.as_str(),
        ];
        for text in bad {
            assert_eq!(
                Digest::parse(text).unwrap_err().rule,
                "sha256:[0-9a-f]{64}",
                "{text}"
            );
        }
    }

    #[test]
    fn digest_of_raw_bytes() {
        let d = Digest::from_sha256([0xab; 32]);
        assert_eq!(d.as_str(), format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(Digest::parse(d.as_str()).unwrap(), d);
    }

    #[test]
    fn ids_serialize_as_strings_and_validate_on_input() {
        let d = Digest::parse(&format!("sha256:{HEX64}")).unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"sha256:{HEX64}\""));
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
        let err = serde_json::from_str::<ServiceName>("\"Bad\"").unwrap_err();
        assert!(err.to_string().contains("service name"));
        assert!(serde_json::from_str::<ServiceName>("5").is_err());
    }
}
