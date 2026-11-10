//! A test Sigstore instance made in-process: a certificate authority standing in for Fulcio
//! (a root and an intermediate), a certificate-transparency log key, a Rekor log key and an
//! RFC 3161 timestamp authority. [`Authority::trusted_root_json`] is its trusted root and
//! [`Authority::bundle`] signs an in-toto statement as a GitHub Actions workflow would, with a
//! log entry, a timestamp, both or neither ([`Evidence`]). Nothing reads the clock: every time
//! derives from [`signed_at`].

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::AssociatedOid;
use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, ID_KP_CODE_SIGNING, ID_SHA_256, SECP_256_R_1,
};
use const_oid::db::rfc6268::{ID_CONTENT_TYPE, ID_MESSAGE_DIGEST};
use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, Uint};
use der::{Any, Encode, Tag};
use dsu_core::config::Signer;
use dsu_core::ids::Digest;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use x509_cert::attr::Attribute;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

/// The Fulcio extension numbers (the last arc of `1.3.6.1.4.1.57264.1.N`) of [`Identity::claims`].
pub mod claim {
    /// `.1.8`: the OIDC issuer.
    pub const ISSUER: u8 = 8;
    /// `.1.9`: the build signer URI (the workflow and its ref).
    pub const BUILD_SIGNER_URI: u8 = 9;
    /// `.1.10`: the build signer commit.
    pub const BUILD_SIGNER_DIGEST: u8 = 10;
    /// `.1.11`: the runner environment, `github-hosted` or `self-hosted`.
    pub const RUNNER_ENVIRONMENT: u8 = 11;
    /// `.1.12`: the source repository URL.
    pub const SOURCE_REPOSITORY_URI: u8 = 12;
    /// `.1.13`: the source commit.
    pub const SOURCE_REPOSITORY_DIGEST: u8 = 13;
    /// `.1.14`: the source ref.
    pub const SOURCE_REPOSITORY_REF: u8 = 14;
    /// `.1.15`: the source repository's numeric id.
    pub const SOURCE_REPOSITORY_IDENTIFIER: u8 = 15;
    /// `.1.16`: the repository owner's URL.
    pub const SOURCE_REPOSITORY_OWNER_URI: u8 = 16;
    /// `.1.17`: the repository owner's numeric id.
    pub const SOURCE_REPOSITORY_OWNER_IDENTIFIER: u8 = 17;
    /// `.1.18`: the build config URI.
    pub const BUILD_CONFIG_URI: u8 = 18;
    /// `.1.19`: the build config commit.
    pub const BUILD_CONFIG_DIGEST: u8 = 19;
    /// `.1.20`: the build trigger, such as `push`.
    pub const BUILD_TRIGGER: u8 = 20;
    /// `.1.21`: the run invocation URI.
    pub const RUN_INVOCATION_URI: u8 = 21;
    /// `.1.22`: the repository visibility.
    pub const SOURCE_REPOSITORY_VISIBILITY: u8 = 22;
    /// `.1.23`: the deployment environment.
    pub const DEPLOYMENT_ENVIRONMENT: u8 = 23;
    /// `.1.24`: the token subject.
    pub const TOKEN_SUBJECT: u8 = 24;
}

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const FULCIO_ARC: &str = "1.3.6.1.4.1.57264.1";
/// The OID of the certificate-transparency precertificate SCT list extension.
const SCT_LIST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");
const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.99.1");
const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The instant the test signatures are made at, 2026-10-01T12:00:00Z. Every certificate,
/// log entry and timestamp is valid then.
pub fn signed_at() -> jiff::Timestamp {
    "2026-10-01T12:00:00Z".parse().unwrap()
}

/// When the test authorities' keys and certificate authorities start to be valid.
fn authority_start() -> jiff::Timestamp {
    "2026-09-15T00:00:00Z".parse().unwrap()
}

/// When the test authorities' certificates end.
fn authority_end() -> jiff::Timestamp {
    "2036-09-15T00:00:00Z".parse().unwrap()
}

/// The signing certificate's lifetime on each side of the signing instant.
const LEAF_MARGIN_SECS: i64 = 300;

/// A P-256 key pair.
struct Key {
    pair: EcdsaKeyPair,
}

impl Key {
    fn generate() -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        Self { pair }
    }

    /// An ASN.1 DER ECDSA signature of SHA-256 over `message`.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    fn spki(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::encode_from(&SECP_256_R_1).unwrap()),
            },
            subject_public_key: BitString::from_bytes(self.pair.public_key().as_ref()).unwrap(),
        }
    }

    fn spki_der(&self) -> Vec<u8> {
        self.spki().to_der().unwrap()
    }

    /// The log or key id: the SHA-256 of the SubjectPublicKeyInfo.
    fn id(&self) -> [u8; 32] {
        Sha256::digest(self.spki_der()).into()
    }
}

/// A certificate and its key.
struct Ca {
    key: Key,
    cert: Certificate,
}

impl Ca {
    fn der(&self) -> Vec<u8> {
        self.cert.to_der().unwrap()
    }

    fn name(&self) -> &Name {
        &self.cert.tbs_certificate.subject
    }
}

fn algorithm_ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA_256,
        parameters: None,
    }
}

fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value).unwrap(),
    }
}

fn typed_extension<T: Encode + AssociatedOid>(critical: bool, value: &T) -> Extension {
    extension(T::OID, critical, value.to_der().unwrap())
}

fn ca_extensions() -> Vec<Extension> {
    vec![
        typed_extension(
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
        ),
        typed_extension(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
    ]
}

fn leaf_extensions(usage: ObjectIdentifier) -> Vec<Extension> {
    vec![
        typed_extension(true, &KeyUsage(KeyUsages::DigitalSignature.into())),
        typed_extension(true, &ExtendedKeyUsage(vec![usage])),
    ]
}

/// The to-be-signed part of a certificate for `subject_key`, issued by `issuer`.
fn tbs(
    subject: Name,
    subject_key: &Key,
    issuer: Name,
    serial: u32,
    window: (jiff::Timestamp, jiff::Timestamp),
    extensions: Vec<Extension>,
) -> TbsCertificate {
    let time = |t: jiff::Timestamp| Time::try_from(SystemTime::from(t)).unwrap();
    TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(serial),
        signature: algorithm_ecdsa_sha256(),
        issuer,
        validity: Validity {
            not_before: time(window.0),
            not_after: time(window.1),
        },
        subject,
        subject_public_key_info: subject_key.spki(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
}

/// `tbs` signed with `issuer_key`.
fn sign_certificate(tbs: TbsCertificate, issuer_key: &Key) -> Certificate {
    let signature = issuer_key.sign(&tbs.to_der().unwrap());
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm_ecdsa_sha256(),
        signature: BitString::from_bytes(&signature).unwrap(),
    }
}

fn name(common_name: &str) -> Name {
    Name::from_str(&format!("CN={common_name},O=dsu-testkit")).unwrap()
}

/// A self-signed CA certificate.
fn root_ca(common_name: &str, serial: u32) -> Ca {
    let key = Key::generate();
    let tbs = tbs(
        name(common_name),
        &key,
        name(common_name),
        serial,
        (authority_start(), authority_end()),
        ca_extensions(),
    );
    let cert = sign_certificate(tbs, &key);
    Ca { key, cert }
}

/// A CA certificate issued by `issuer`.
fn issued_ca(common_name: &str, serial: u32, issuer: &Ca) -> Ca {
    let key = Key::generate();
    let tbs = tbs(
        name(common_name),
        &key,
        issuer.name().clone(),
        serial,
        (authority_start(), authority_end()),
        ca_extensions(),
    );
    let cert = sign_certificate(tbs, &issuer.key);
    Ca { key, cert }
}

/// The Fulcio claims of a signing certificate: a subject alternative name and the extensions
/// `1.3.6.1.4.1.57264.1.8` to `.24`. Tests change a field to make a certificate that is
/// signed by another workflow, ref, repository, trigger or runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The subject alternative name (a URI): `https://github.com/<repository>/<workflow>@<ref>`.
    pub san: String,
    /// The extension values by [`claim`] number. The issuer (`.1.8`) is also written as the
    /// deprecated raw `.1.1`; the others are DER UTF-8 strings.
    pub claims: BTreeMap<u8, String>,
}

impl Identity {
    /// The identity of a workflow run of `signer` (the repository, workflow and ref it names, its
    /// repository id, on a GitHub-hosted runner) started by `trigger`.
    pub fn for_signer(signer: &Signer, trigger: &str) -> Self {
        let repository_url = format!("https://github.com/{}", signer.repository);
        let owner = signer.repository.split('/').next().unwrap();
        let workflow = format!("{repository_url}/{}@{}", signer.workflow, signer.git_ref);
        let claims = [
            (claim::ISSUER, ISSUER.to_owned()),
            (claim::BUILD_SIGNER_URI, workflow.clone()),
            (claim::BUILD_SIGNER_DIGEST, COMMIT.to_owned()),
            (claim::RUNNER_ENVIRONMENT, "github-hosted".to_owned()),
            (claim::SOURCE_REPOSITORY_URI, repository_url.clone()),
            (claim::SOURCE_REPOSITORY_DIGEST, COMMIT.to_owned()),
            (claim::SOURCE_REPOSITORY_REF, signer.git_ref.clone()),
            (
                claim::SOURCE_REPOSITORY_IDENTIFIER,
                signer.repository_id.clone(),
            ),
            (
                claim::SOURCE_REPOSITORY_OWNER_URI,
                format!("https://github.com/{owner}"),
            ),
            (claim::SOURCE_REPOSITORY_OWNER_IDENTIFIER, "1000".to_owned()),
            (claim::BUILD_CONFIG_URI, workflow.clone()),
            (claim::BUILD_CONFIG_DIGEST, COMMIT.to_owned()),
            (claim::BUILD_TRIGGER, trigger.to_owned()),
            (
                claim::RUN_INVOCATION_URI,
                format!("{repository_url}/actions/runs/1234567890/attempts/1"),
            ),
            (claim::SOURCE_REPOSITORY_VISIBILITY, "public".to_owned()),
            (claim::DEPLOYMENT_ENVIRONMENT, "production".to_owned()),
            (
                claim::TOKEN_SUBJECT,
                format!("repo:{}:ref:{}", signer.repository, signer.git_ref),
            ),
        ];
        Self {
            san: workflow,
            claims: claims.into_iter().collect(),
        }
    }

    fn extensions(&self) -> Vec<Extension> {
        let fulcio = |arc: u8| ObjectIdentifier::new(&format!("{FULCIO_ARC}.{arc}")).unwrap();
        let san = GeneralName::UniformResourceIdentifier(self.san.clone().try_into().unwrap());
        let mut extensions = vec![typed_extension(true, &SubjectAltName(vec![san]))];
        for (arc, value) in &self.claims {
            extensions.push(extension(fulcio(*arc), false, value.to_der().unwrap()));
        }
        if let Some(issuer) = self.claims.get(&claim::ISSUER) {
            extensions.push(extension(fulcio(1), false, issuer.clone().into_bytes()));
        }
        extensions
    }
}

/// The evidence of when a bundle was signed that the minted bundle carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// A transparency-log entry only (what Sigstore's public-good instance signs).
    Log,
    /// A transparency-log entry whose integrated time was changed after the log signed it.
    AlteredLog,
    /// An RFC 3161 timestamp only, no log entry (what GitHub's own instance signs).
    Timestamp,
    /// A log entry and a timestamp.
    LogAndTimestamp,
    /// Neither: nothing proves when the signature was made.
    Neither,
}

/// One subject of the signed in-toto statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The artifact's file name.
    pub name: String,
    /// The artifact's SHA-256, 64 lower-case hex digits.
    pub sha256: String,
}

/// What a minted bundle says and carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// The statement's `_type`.
    pub statement_type: String,
    /// The statement's `predicateType`.
    pub predicate_type: String,
    /// The statement's subjects.
    pub subjects: Vec<Subject>,
    /// The identity of the signing certificate.
    pub identity: Identity,
    /// What proves when it was signed.
    pub evidence: Evidence,
    /// The signing instant: the log's integrated time and the timestamp's time.
    pub signed_at: jiff::Timestamp,
}

impl Spec {
    /// SLSA provenance v1 for one artifact `name` with the SHA-256 `tar`, signed at
    /// [`signed_at`] by `signer`'s first trigger, with a log entry.
    pub fn github(signer: &Signer, name: &str, tar: &Digest) -> Self {
        Self {
            statement_type: "https://in-toto.io/Statement/v1".to_owned(),
            predicate_type: "https://slsa.dev/provenance/v1".to_owned(),
            subjects: vec![Subject {
                name: name.to_owned(),
                sha256: tar.hex().to_owned(),
            }],
            identity: Identity::for_signer(signer, &signer.triggers[0]),
            evidence: Evidence::Log,
            signed_at: signed_at(),
        }
    }

    fn statement(&self) -> Vec<u8> {
        let subjects: Vec<Value> = self
            .subjects
            .iter()
            .map(|s| json!({"name": s.name, "digest": {"sha256": s.sha256}}))
            .collect();
        let statement = json!({
            "_type": self.statement_type,
            "subject": subjects,
            "predicateType": self.predicate_type,
            "predicate": {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1"}},
        });
        statement.to_string().into_bytes()
    }
}

/// The DER of a SEQUENCE whose elements are the DER encodings `parts`.
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    Any::new(Tag::Sequence, parts.concat())
        .unwrap()
        .to_der()
        .unwrap()
}

/// A test Sigstore instance: its keys and certificates, made fresh by every
/// [`Authority::public_good`].
pub struct Authority {
    root: Ca,
    intermediate: Ca,
    ct_log: Option<Key>,
    rekor: Option<Key>,
    tsa_root: Ca,
    tsa: Ca,
}

impl Authority {
    /// An instance like Sigstore's public-good one: a certificate-transparency log (the signing
    /// certificates carry its SCT), a Rekor log and a timestamp authority.
    pub fn public_good() -> Self {
        let root = root_ca("test fulcio root", 1);
        let intermediate = issued_ca("test fulcio intermediate", 2, &root);
        let tsa_root = root_ca("test tsa root", 3);
        let tsa = {
            let key = Key::generate();
            let issuer = tsa_root.name().clone();
            let extensions = leaf_extensions(ID_KP_TIME_STAMPING);
            let tbs = tbs(
                name("test tsa"),
                &key,
                issuer,
                4,
                (authority_start(), authority_end()),
                extensions,
            );
            let cert = sign_certificate(tbs, &tsa_root.key);
            Ca { key, cert }
        };
        Self {
            root,
            intermediate,
            ct_log: Some(Key::generate()),
            rekor: Some(Key::generate()),
            tsa_root,
            tsa,
        }
    }

    /// An instance like GitHub's own: no certificate-transparency log (signing certificates
    /// carry no SCT) and no Rekor log, only a timestamp authority.
    pub fn without_logs() -> Self {
        Self {
            ct_log: None,
            rekor: None,
            ..Self::public_good()
        }
    }

    /// The instance's trusted root, in the JSON `gh attestation trusted-root` writes.
    pub fn trusted_root_json(&self) -> String {
        let valid_for = json!({"start": authority_start().to_string()});
        let log = |url: &str, key: &Key| {
            json!({
                "baseUrl": url,
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": STANDARD.encode(key.spki_der()),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": valid_for,
                },
                "logId": {"keyId": STANDARD.encode(key.id())},
            })
        };
        let chain = |certificates: [&Ca; 2]| json!({"certificates": certificates.map(|ca| json!({"rawBytes": STANDARD.encode(ca.der())}))});
        let tlogs: Vec<Value> = self
            .rekor
            .iter()
            .map(|key| log("https://rekor.test.invalid", key))
            .collect();
        let ctlogs: Vec<Value> = self
            .ct_log
            .iter()
            .map(|key| log("https://ct.test.invalid", key))
            .collect();
        json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": tlogs,
            "certificateAuthorities": [{
                "subject": {"organization": "dsu-testkit", "commonName": "test fulcio"},
                "uri": "https://fulcio.test.invalid",
                "certChain": chain([&self.intermediate, &self.root]),
                "validFor": valid_for,
            }],
            "ctlogs": ctlogs,
            "timestampAuthorities": [{
                "subject": {"organization": "dsu-testkit", "commonName": "test tsa"},
                "uri": "https://tsa.test.invalid",
                "certChain": chain([&self.tsa, &self.tsa_root]),
                "validFor": valid_for,
            }],
        })
        .to_string()
    }

    /// A Sigstore bundle (v0.3, a DSSE envelope signed with a fresh Fulcio-style certificate)
    /// as `spec` describes. Panics when `spec.evidence` asks for a log entry and this
    /// instance has no log.
    pub fn bundle(&self, spec: &Spec) -> Value {
        let leaf_key = Key::generate();
        let window = (
            spec.signed_at - jiff::SignedDuration::from_secs(LEAF_MARGIN_SECS),
            spec.signed_at + jiff::SignedDuration::from_secs(LEAF_MARGIN_SECS),
        );
        let certificate = self.signing_certificate(&leaf_key, window, &spec.identity);

        let payload = spec.statement();
        let signature = leaf_key.sign(&dsse_pae(PAYLOAD_TYPE, &payload));
        let envelope = json!({
            "payload": STANDARD.encode(&payload),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{"sig": STANDARD.encode(&signature)}],
        });

        let with_log = matches!(
            spec.evidence,
            Evidence::Log | Evidence::AlteredLog | Evidence::LogAndTimestamp
        );
        let with_timestamp = matches!(
            spec.evidence,
            Evidence::Timestamp | Evidence::LogAndTimestamp
        );
        let tlog_entries: Vec<Value> = if with_log {
            let altered = spec.evidence == Evidence::AlteredLog;
            vec![self.log_entry(spec, &envelope, &payload, &signature, &certificate, altered)]
        } else {
            Vec::new()
        };
        let timestamps: Vec<Value> = if with_timestamp {
            let token = self.timestamp_token(&signature, spec.signed_at);
            vec![json!({"signedTimestamp": STANDARD.encode(token)})]
        } else {
            Vec::new()
        };
        let timestamp_data = if timestamps.is_empty() {
            json!({})
        } else {
            json!({"rfc3161Timestamps": timestamps})
        };

        json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": STANDARD.encode(certificate.to_der().unwrap())},
                "tlogEntries": tlog_entries,
                "timestampVerificationData": timestamp_data,
            },
            "dsseEnvelope": envelope,
        })
    }

    /// The signing certificate: issued by the intermediate to `key`, carrying `identity` and,
    /// when the instance has a certificate-transparency log, that log's embedded SCT.
    fn signing_certificate(
        &self,
        key: &Key,
        window: (jiff::Timestamp, jiff::Timestamp),
        identity: &Identity,
    ) -> Certificate {
        let issuer = self.intermediate.name().clone();
        let mut extensions = leaf_extensions(ID_KP_CODE_SIGNING);
        extensions.extend(identity.extensions());
        let precert = tbs(
            Name::default(),
            key,
            issuer.clone(),
            100,
            window,
            extensions.clone(),
        );
        if let Some(log) = &self.ct_log {
            extensions.push(self.sct_extension(log, &precert, window.0));
        }
        let tbs = tbs(Name::default(), key, issuer, 100, window, extensions);
        sign_certificate(tbs, &self.intermediate.key)
    }

    /// The SCT list extension: `log`'s signature over `precert` (the certificate without it).
    fn sct_extension(&self, log: &Key, precert: &TbsCertificate, at: jiff::Timestamp) -> Extension {
        let millis = u64::try_from(at.as_millisecond()).unwrap();
        let tbs = precert.to_der().unwrap();
        let mut signed = vec![0, 0];
        signed.extend(millis.to_be_bytes());
        signed.extend([0, 1]);
        signed.extend(Sha256::digest(self.intermediate.key.spki_der()));
        signed.extend(&u64::try_from(tbs.len()).unwrap().to_be_bytes()[5..]);
        signed.extend(&tbs);
        signed.extend([0, 0]);
        let signature = log.sign(&signed);

        let mut sct = vec![0];
        sct.extend(log.id());
        sct.extend(millis.to_be_bytes());
        sct.extend([0, 0, 4, 3]);
        sct.extend(u16::try_from(signature.len()).unwrap().to_be_bytes());
        sct.extend(&signature);
        let mut list = u16::try_from(sct.len()).unwrap().to_be_bytes().to_vec();
        list.extend(&sct);
        let mut tls = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
        tls.extend(&list);
        extension(
            SCT_LIST,
            false,
            OctetString::new(tls).unwrap().to_der().unwrap(),
        )
    }

    /// A `dsse` v0.0.1 log entry for the envelope, in a two-leaf tree whose checkpoint the log
    /// signed. `altered` shows an integrated time one second later than the log signed.
    fn log_entry(
        &self,
        spec: &Spec,
        envelope: &Value,
        payload: &[u8],
        signature: &[u8],
        certificate: &Certificate,
        altered: bool,
    ) -> Value {
        let log = self
            .rekor
            .as_ref()
            .expect("this authority has no transparency log");
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let log_id = log.id();
        let integrated = spec.signed_at.as_second();
        let log_index: u64 = 7_000_001;

        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD
                .encode(certificate.to_der().unwrap())
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let body = json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "envelopeHash": {"algorithm": "sha256", "value": hex(&Sha256::digest(envelope.to_string()))},
                "payloadHash": {"algorithm": "sha256", "value": hex(&Sha256::digest(payload))},
                "signatures": [{"signature": STANDARD.encode(signature), "verifier": STANDARD.encode(pem)}],
            },
        })
        .to_string()
        .into_bytes();

        let leaf = Sha256::new()
            .chain_update([0])
            .chain_update(&body)
            .finalize();
        let sibling = Sha256::new()
            .chain_update([0])
            .chain_update(b"test log sibling")
            .finalize();
        let root = Sha256::new()
            .chain_update([1])
            .chain_update(sibling)
            .chain_update(leaf)
            .finalize();
        let signed_note = format!(
            "log.test.invalid - {}\n2\n{}\n",
            hex(&log_id[..8]),
            STANDARD.encode(root)
        );
        let mut hinted = log_id[..4].to_vec();
        hinted.extend(log.sign(signed_note.as_bytes()));
        let checkpoint = format!(
            "{signed_note}\n\u{2014} log.test.invalid {}\n",
            STANDARD.encode(hinted)
        );

        let set_message = format!(
            r#"{{"body":"{}","integratedTime":{integrated},"logID":"{}","logIndex":{log_index}}}"#,
            STANDARD.encode(&body),
            hex(&log_id)
        );
        let shown_time = integrated + i64::from(altered);
        json!({
            "logIndex": log_index.to_string(),
            "logId": {"keyId": STANDARD.encode(log_id)},
            "kindVersion": {"kind": "dsse", "version": "0.0.1"},
            "integratedTime": shown_time.to_string(),
            "inclusionPromise": {"signedEntryTimestamp": STANDARD.encode(log.sign(set_message.as_bytes()))},
            "inclusionProof": {
                "logIndex": "1",
                "rootHash": STANDARD.encode(root),
                "treeSize": "2",
                "hashes": [STANDARD.encode(sibling)],
                "checkpoint": {"envelope": checkpoint},
            },
            "canonicalizedBody": STANDARD.encode(&body),
        })
    }

    /// An RFC 3161 time-stamp token (a CMS `SignedData` of a `TSTInfo`) over `signature`, made
    /// by the timestamp authority at `at`.
    fn timestamp_token(&self, signature: &[u8], at: jiff::Timestamp) -> Vec<u8> {
        let sha256 = AlgorithmIdentifierOwned {
            oid: ID_SHA_256,
            parameters: None,
        };
        let gen_time =
            GeneralizedTime::from_unix_duration(Duration::from_secs(at.as_second().unsigned_abs()))
                .unwrap();
        let imprint = sequence(&[
            sha256.to_der().unwrap(),
            OctetString::new(Sha256::digest(signature).to_vec())
                .unwrap()
                .to_der()
                .unwrap(),
        ]);
        let tst_info = sequence(&[
            1u8.to_der().unwrap(),
            TSA_POLICY.to_der().unwrap(),
            imprint,
            Uint::new(&[1]).unwrap().to_der().unwrap(),
            gen_time.to_der().unwrap(),
        ]);

        let attribute = |oid: ObjectIdentifier, value: Any| Attribute {
            oid,
            values: SetOfVec::try_from(vec![value]).unwrap(),
        };
        let digest = OctetString::new(Sha256::digest(&tst_info).to_vec()).unwrap();
        let signed_attrs = SetOfVec::try_from(vec![
            attribute(ID_CONTENT_TYPE, Any::encode_from(&TST_INFO).unwrap()),
            attribute(ID_MESSAGE_DIGEST, Any::encode_from(&digest).unwrap()),
        ])
        .unwrap();
        let attrs_signature = self.tsa.key.sign(&signed_attrs.to_der().unwrap());

        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.tsa.cert.tbs_certificate.issuer.clone(),
                serial_number: self.tsa.cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: algorithm_ecdsa_sha256(),
            signature: OctetString::new(attrs_signature).unwrap(),
            unsigned_attrs: None,
        };
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256]).unwrap(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: TST_INFO,
                econtent: Some(Any::encode_from(&OctetString::new(tst_info).unwrap()).unwrap()),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer]).unwrap()),
        };
        ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).unwrap(),
        }
        .to_der()
        .unwrap()
    }
}

/// The DSSE pre-authentication encoding of a payload.
fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    pae.extend(payload);
    pae
}

#[cfg(test)]
mod tests {
    use sigstore_verify::trust_root::TrustedRoot;
    use sigstore_verify::types::{ArtifactDigest, Bundle, Sha256Hash};
    use sigstore_verify::{VerificationPolicy, Verifier};

    use super::*;

    fn signer() -> Signer {
        Signer {
            repository: "example-org/app".to_owned(),
            repository_id: "4242".to_owned(),
            workflow: ".github/workflows/release.yml".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            triggers: vec!["push".to_owned()],
        }
    }

    /// Verifies a bundle minted for `evidence` the way the signer's relying party must: the
    /// log is skipped for a bundle without a log entry, the SCT for an instance without a log.
    fn verified_times(authority: &Authority, evidence: Evidence) -> Option<Vec<jiff::Timestamp>> {
        let tar = Digest::from_sha256(Sha256::digest(b"tar").into());
        let mut spec = Spec::github(&signer(), "app.tar", &tar);
        spec.evidence = evidence;
        let bundle = Bundle::from_json(&authority.bundle(&spec).to_string()).unwrap();
        let root = TrustedRoot::from_json(&authority.trusted_root_json()).unwrap();
        let mut policy = VerificationPolicy::any_identity();
        if bundle.verification_material.tlog_entries.is_empty() {
            policy = policy.skip_tlog_unsafe();
        }
        if authority.ct_log.is_none() {
            policy = policy.skip_sct();
        }
        let digest = ArtifactDigest::sha256(Sha256Hash::from_hex(tar.hex()).unwrap());
        let result = Verifier::new(&root)
            .unwrap()
            .verify(digest, &bundle, &policy)
            .ok()?;
        Some(result.verified_timestamps().to_vec())
    }

    #[test]
    fn each_kind_of_evidence_verifies_or_fails_as_named() {
        let at = signed_at();
        let public_good = Authority::public_good();
        assert_eq!(verified_times(&public_good, Evidence::Log), Some(vec![at]));
        assert_eq!(
            verified_times(&public_good, Evidence::Timestamp),
            Some(vec![at])
        );
        assert_eq!(
            verified_times(&public_good, Evidence::LogAndTimestamp),
            Some(vec![at, at])
        );
        assert_eq!(verified_times(&public_good, Evidence::AlteredLog), None);
        assert_eq!(verified_times(&public_good, Evidence::Neither), None);

        let without_logs = Authority::without_logs();
        assert_eq!(
            verified_times(&without_logs, Evidence::Timestamp),
            Some(vec![at])
        );
        assert_eq!(verified_times(&without_logs, Evidence::Neither), None);
    }

    #[test]
    fn the_identity_carries_every_fulcio_extension() {
        let mut identity = Identity::for_signer(&signer(), "push");
        let numbers: Vec<u8> = identity.claims.keys().copied().collect();
        assert_eq!(numbers, (8..=24).collect::<Vec<u8>>());
        assert_eq!(identity.san, identity.claims[&claim::BUILD_SIGNER_URI]);
        // the SAN, the 17 claims and the legacy issuer
        assert_eq!(identity.extensions().len(), 1 + 17 + 1);
        // without an issuer, neither of its two extensions is written
        identity.claims.remove(&claim::ISSUER);
        assert_eq!(identity.extensions().len(), 1 + 16);
    }
}
