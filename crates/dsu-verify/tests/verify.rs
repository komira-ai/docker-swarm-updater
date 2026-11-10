//! The 'bundle' rows of docs/design.md section 6, made with the test signing chain of
//! `dsu_testkit::mint`, and real GitHub attestation bundles verified offline.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use dsu_core::config::Signer;
use dsu_core::ids::Digest;
use dsu_testkit::mint::{Authority, Evidence, Identity, Spec, Subject, claim, signed_at};
use dsu_verify::{
    KeyValidity, RootError, TrustedRoots, Verified, VerifyError, VerifyInput, verify,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const NAME: &str = "app-1.2.3-linux-x86_64.oci.tar";
const PATTERN: &str = "app-*-linux-x86_64.oci.tar";

fn signer() -> Signer {
    Signer {
        repository: "example-org/app".to_owned(),
        repository_id: "4242".to_owned(),
        workflow: ".github/workflows/release.yml".to_owned(),
        git_ref: "refs/heads/main".to_owned(),
        triggers: vec!["push".to_owned(), "workflow_dispatch".to_owned()],
    }
}

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::from_sha256(Sha256::digest(bytes).into())
}

fn tar() -> Digest {
    digest_of(b"the image tar")
}

fn spec() -> Spec {
    Spec::github(&signer(), NAME, &tar())
}

fn roots_of(authority: &Authority) -> TrustedRoots {
    TrustedRoots::parse(authority.trusted_root_json().as_bytes()).unwrap()
}

fn run(
    roots: &TrustedRoots,
    bundle: &[u8],
    tar: &Digest,
    signer: &Signer,
    pattern: &str,
) -> Result<Verified, VerifyError> {
    verify(&VerifyInput {
        bundle,
        roots,
        tar_digest: tar,
        signer,
        artifact_name: pattern,
    })
}

/// Verifies `bundle` as the configured service would.
fn check(roots: &TrustedRoots, bundle: &Value) -> Result<Verified, VerifyError> {
    run(
        roots,
        bundle.to_string().as_bytes(),
        &tar(),
        &signer(),
        PATTERN,
    )
}

/// `bundle` with `edit` applied.
fn edited(bundle: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut bundle = bundle.clone();
    edit(&mut bundle);
    bundle
}

fn assert_token(result: Result<Verified, VerifyError>, token: &str) -> VerifyError {
    let error = result.unwrap_err();
    assert_eq!(error.token(), token, "{error}");
    assert!(!error.detail().is_empty());
    assert!(!error.detail().contains('\n'));
    error
}

#[test]
fn a_good_release_verifies() {
    let authority = Authority::public_good();
    let verified = check(&roots_of(&authority), &authority.bundle(&spec())).unwrap();
    assert_eq!(
        verified,
        Verified {
            signed_time: signed_at(),
            subject_name: NAME.to_owned()
        }
    );
}

#[test]
fn a_bundle_that_is_not_json_is_invalid() {
    let roots = roots_of(&Authority::public_good());
    for bytes in [&b"not json"[..], b"{}", b"\xff\xfe", b""] {
        assert_token(
            run(&roots, bytes, &tar(), &signer(), PATTERN),
            "bundle_invalid",
        );
    }
}

#[test]
fn a_tar_changed_after_signing_is_refused_by_subject() {
    let authority = Authority::public_good();
    let bundle = authority.bundle(&spec());
    let changed = digest_of(b"the image tar, changed");
    let result = run(
        &roots_of(&authority),
        bundle.to_string().as_bytes(),
        &changed,
        &signer(),
        PATTERN,
    );
    let error = assert_token(result, "bundle_subject");
    assert!(error.detail().contains(changed.hex()), "{error}");
}

#[test]
fn a_valid_bundle_of_another_artifact_of_the_release_is_refused_by_subject() {
    let authority = Authority::public_good();
    let mut other = spec();
    other.subjects = vec![Subject {
        name: "app-1.2.3-linux-x86_64.bin".to_owned(),
        sha256: digest_of(b"binary").hex().to_owned(),
    }];
    let result = check(&roots_of(&authority), &authority.bundle(&other));
    assert_token(result, "bundle_subject");
}

#[test]
fn a_subject_needs_both_the_name_and_the_digest() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    let right_name_wrong_digest = Subject {
        name: NAME.to_owned(),
        sha256: digest_of(b"other").hex().to_owned(),
    };
    let wrong_name_right_digest = Subject {
        name: "other.tar".to_owned(),
        sha256: tar().hex().to_owned(),
    };
    for subject in [right_name_wrong_digest, wrong_name_right_digest] {
        let mut spec = spec();
        spec.subjects = vec![subject];
        assert_token(check(&roots, &authority.bundle(&spec)), "bundle_subject");
    }
    let mut spec = spec();
    spec.subjects = vec![Subject {
        name: "other.tar".to_owned(),
        sha256: tar().hex().to_owned(),
    }];
    spec.subjects.push(Subject {
        name: NAME.to_owned(),
        sha256: tar().hex().to_owned(),
    });
    spec.subjects.push(Subject {
        name: "another.tar".to_owned(),
        sha256: digest_of(b"x").hex().to_owned(),
    });
    let verified = check(&roots, &authority.bundle(&spec)).unwrap();
    assert_eq!(verified.subject_name, NAME);
}

#[test]
fn artifact_name_patterns_have_one_star() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    let mut spec = spec();
    spec.subjects[0].name = "abc".to_owned();
    let bundle = authority.bundle(&spec).to_string().into_bytes();
    let matches = |pattern: &str| run(&roots, &bundle, &tar(), &signer(), pattern).is_ok();
    // The config's matcher: one `*` standing for one or more characters other than `/`.
    assert!(matches("*"));
    assert!(matches("a*"));
    assert!(matches("*c"));
    assert!(matches("a*c"));
    assert!(!matches("ab*c"));
    assert!(!matches("abc*"));
    assert!(!matches("*abc"));
    assert!(!matches("abc"));
    assert!(!matches("b*"));
}

#[test]
fn a_message_signature_is_not_an_attestation() {
    let roots = roots_of(&Authority::public_good());
    let bundle = json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"publicKey": {"hint": "key"}, "tlogEntries": []},
        "messageSignature": {"signature": "AAAA"},
    });
    let error = assert_token(check(&roots, &bundle), "bundle_subject");
    assert!(error.detail().contains("message signature"), "{error}");
}

#[test]
fn the_statement_must_be_in_toto_slsa_provenance_v1() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    let good = authority.bundle(&spec());

    let wrong_payload_type = edited(&good, |b| {
        b["dsseEnvelope"]["payloadType"] = json!("text/plain")
    });
    let error = assert_token(check(&roots, &wrong_payload_type), "bundle_subject");
    assert!(error.detail().contains("payload type"), "{error}");

    for payload in [
        &b"not json"[..],
        br#"{"_type":"https://in-toto.io/Statement/v1"}"#,
    ] {
        let not_a_statement = edited(&good, |b| {
            b["dsseEnvelope"]["payload"] = json!(base64(payload))
        });
        let error = assert_token(check(&roots, &not_a_statement), "bundle_subject");
        assert!(
            error.detail().contains("not an in-toto statement"),
            "{error}"
        );
    }

    let mut spec = spec();
    spec.statement_type = "https://in-toto.io/Statement/v0.1".to_owned();
    let error = assert_token(check(&roots, &authority.bundle(&spec)), "bundle_subject");
    assert!(error.detail().contains("statement type"), "{error}");

    let mut spec = self::spec();
    spec.predicate_type = "https://example.test/predicate/v1".to_owned();
    let error = assert_token(check(&roots, &authority.bundle(&spec)), "bundle_subject");
    assert!(error.detail().contains("predicate type"), "{error}");
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A signer that differs from the configured one only by `change`.
fn signed_by(change: impl FnOnce(&mut Signer)) -> Spec {
    let mut other = signer();
    change(&mut other);
    let mut spec = spec();
    spec.identity = Identity::for_signer(&other, &other.triggers[0]);
    spec
}

fn assert_signer_refused(spec: &Spec, detail: &str) {
    let authority = Authority::public_good();
    let error = assert_token(
        check(&roots_of(&authority), &authority.bundle(spec)),
        "bundle_signer",
    );
    assert!(error.detail().contains(detail), "{error}");
}

#[test]
fn another_workflow_ref_or_repository_is_refused_by_signer() {
    assert_signer_refused(
        &signed_by(|s| s.workflow = ".github/workflows/other.yml".to_owned()),
        "certificate identity",
    );
    assert_signer_refused(
        &signed_by(|s| s.git_ref = "refs/heads/feature".to_owned()),
        "certificate identity",
    );
    assert_signer_refused(
        &signed_by(|s| s.repository = "example-org/other".to_owned()),
        "certificate identity",
    );
}

#[test]
fn another_repository_id_is_refused_by_signer() {
    assert_signer_refused(
        &signed_by(|s| s.repository_id = "4243".to_owned()),
        "repository id",
    );
}

#[test]
fn another_trigger_is_refused_by_signer() {
    let mut spec = spec();
    spec.identity = Identity::for_signer(&signer(), "pull_request");
    assert_signer_refused(&spec, "build trigger");
    // every configured trigger is accepted
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    spec.identity = Identity::for_signer(&signer(), "workflow_dispatch");
    check(&roots, &authority.bundle(&spec)).unwrap();
}

#[test]
fn a_self_hosted_runner_is_refused_by_signer() {
    let mut spec = spec();
    spec.identity
        .claims
        .insert(claim::RUNNER_ENVIRONMENT, "self-hosted".to_owned());
    assert_signer_refused(&spec, "runner environment");
}

#[test]
fn a_run_of_another_repository_is_refused_by_signer() {
    let mut spec = spec();
    spec.identity.claims.insert(
        claim::RUN_INVOCATION_URI,
        "https://github.com/example-org/other/actions/runs/7/attempts/1".to_owned(),
    );
    assert_signer_refused(&spec, "run invocation URI");
    // the repository name is a prefix of the other one
    spec.identity.claims.insert(
        claim::RUN_INVOCATION_URI,
        "https://github.com/example-org/app-fork/actions/runs/7".to_owned(),
    );
    assert_signer_refused(&spec, "run invocation URI");
}

#[test]
fn another_token_issuer_is_refused_by_signer() {
    let mut spec = spec();
    spec.identity
        .claims
        .insert(claim::ISSUER, "https://accounts.example.test".to_owned());
    assert_signer_refused(&spec, "token issuer");
}

#[test]
fn a_certificate_without_the_claims_is_refused_by_signer() {
    for number in [
        claim::ISSUER,
        claim::SOURCE_REPOSITORY_IDENTIFIER,
        claim::RUNNER_ENVIRONMENT,
        claim::BUILD_TRIGGER,
        claim::RUN_INVOCATION_URI,
    ] {
        let mut spec = spec();
        spec.identity.claims.remove(&number);
        assert_signer_refused(&spec, "None");
    }
}

#[test]
fn a_chain_from_another_root_is_refused() {
    let signing = Authority::public_good();
    let trusted = Authority::public_good();
    assert_token(
        check(&roots_of(&trusted), &signing.bundle(&spec())),
        "bundle_chain",
    );

    // the logs and the timestamp authority are the signer's, only the certificate authority is
    // another one: the certificate chain is what fails
    let foreign_ca: Value = serde_json::from_str(&trusted.trusted_root_json()).unwrap();
    for evidence in [Evidence::Log, Evidence::Timestamp] {
        let mut root: Value = serde_json::from_str(&signing.trusted_root_json()).unwrap();
        root["certificateAuthorities"] = foreign_ca["certificateAuthorities"].clone();
        let roots = TrustedRoots::parse(root.to_string().as_bytes()).unwrap();
        let mut spec = spec();
        spec.evidence = evidence;
        let error = assert_token(check(&roots, &signing.bundle(&spec)), "bundle_chain");
        assert!(
            error
                .detail()
                .contains("certificate chain validation failed"),
            "{error}"
        );
    }
}

#[test]
fn a_timestamp_from_another_authority_is_refused() {
    let signing = Authority::public_good();
    let trusted = Authority::public_good();
    let foreign_tsa: Value = serde_json::from_str(&trusted.trusted_root_json()).unwrap();
    let mut root: Value = serde_json::from_str(&signing.trusted_root_json()).unwrap();
    root["timestampAuthorities"] = foreign_tsa["timestampAuthorities"].clone();
    let roots = TrustedRoots::parse(root.to_string().as_bytes()).unwrap();
    let mut spec = spec();
    spec.evidence = Evidence::Timestamp;
    let error = assert_token(check(&roots, &signing.bundle(&spec)), "bundle_chain");
    assert!(error.detail().contains("timestamp"), "{error}");
}

#[test]
fn a_certificate_without_the_log_sct_is_refused() {
    // signed by an instance without a certificate-transparency log, checked by one with
    let without = Authority::without_logs();
    let mut spec = spec();
    spec.evidence = Evidence::Timestamp;
    let bundle = without.bundle(&spec);
    let mut root: Value = serde_json::from_str(&without.trusted_root_json()).unwrap();
    root["ctlogs"] = serde_json::from_str::<Value>(&Authority::public_good().trusted_root_json())
        .unwrap()["ctlogs"]
        .clone();
    let roots = TrustedRoots::parse(root.to_string().as_bytes()).unwrap();
    let error = assert_token(check(&roots, &bundle), "bundle_chain");
    assert!(
        error.detail().contains("SCT") || error.detail().contains("Signed Certificate Timestamp"),
        "{error}"
    );
}

#[test]
fn an_altered_log_entry_is_refused() {
    let authority = Authority::public_good();
    let mut spec = spec();
    spec.evidence = Evidence::AlteredLog;
    let error = assert_token(
        check(&roots_of(&authority), &authority.bundle(&spec)),
        "bundle_chain",
    );
    assert!(error.detail().contains("inclusion promise"), "{error}");
}

#[test]
fn a_log_entry_for_another_signature_is_refused() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    let good = authority.bundle(&spec());
    let other = authority.bundle(&spec());
    let swapped = edited(&good, |b| {
        b["verificationMaterial"]["tlogEntries"] =
            other["verificationMaterial"]["tlogEntries"].clone();
    });
    assert_token(check(&roots, &swapped), "bundle_chain");
}

#[test]
fn a_timestamp_without_a_log_entry_verifies() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    for evidence in [Evidence::Timestamp, Evidence::LogAndTimestamp] {
        let mut spec = spec();
        spec.evidence = evidence;
        let verified = check(&roots, &authority.bundle(&spec)).unwrap();
        assert_eq!(verified.signed_time, signed_at());
    }
}

#[test]
fn the_earliest_verified_time_is_the_signed_time() {
    let authority = Authority::public_good();
    let roots = roots_of(&authority);
    let mut spec = spec();
    spec.evidence = Evidence::LogAndTimestamp;
    spec.signed_at = signed_at() + jiff::SignedDuration::from_secs(90);
    let verified = check(&roots, &authority.bundle(&spec)).unwrap();
    assert_eq!(verified.signed_time, spec.signed_at);
}

#[test]
fn an_instance_without_logs_verifies_a_timestamp() {
    let authority = Authority::without_logs();
    let mut spec = spec();
    spec.evidence = Evidence::Timestamp;
    let verified = check(&roots_of(&authority), &authority.bundle(&spec)).unwrap();
    assert_eq!(verified.signed_time, signed_at());
}

#[test]
fn neither_a_log_entry_nor_a_timestamp_is_refused() {
    for authority in [Authority::public_good(), Authority::without_logs()] {
        let mut spec = spec();
        spec.evidence = Evidence::Neither;
        assert_token(
            check(&roots_of(&authority), &authority.bundle(&spec)),
            "bundle_chain",
        );
    }
}

#[test]
fn a_bundle_without_a_signing_certificate_is_refused() {
    let authority = Authority::public_good();
    let good = authority.bundle(&spec());
    let keyless = edited(&good, |b| {
        let material = &mut b["verificationMaterial"];
        material.as_object_mut().unwrap().remove("certificate");
        material["publicKey"] = json!({"hint": "key"});
    });
    assert_token(check(&roots_of(&authority), &keyless), "bundle_chain");
}

#[test]
fn a_tampered_statement_is_refused() {
    let authority = Authority::public_good();
    let good = authority.bundle(&spec());
    let mut other = spec();
    other.subjects[0].name = "app-9.9.9-linux-x86_64.oci.tar".to_owned();
    let tampered = edited(&good, |b| {
        b["dsseEnvelope"]["payload"] = authority.bundle(&other)["dsseEnvelope"]["payload"].clone()
    });
    assert_token(check(&roots_of(&authority), &tampered), "bundle_chain");
}

#[test]
fn the_second_root_of_a_file_may_be_the_one_that_matches() {
    let signing = Authority::public_good();
    let other = Authority::public_good();
    let file = format!(
        "{}\n{}\n",
        other.trusted_root_json(),
        signing.trusted_root_json()
    );
    let roots = TrustedRoots::parse(file.as_bytes()).unwrap();
    check(&roots, &signing.bundle(&spec())).unwrap();
    // and the first
    let file = format!(
        "{}\n{}\n",
        signing.trusted_root_json(),
        other.trusted_root_json()
    );
    check(
        &TrustedRoots::parse(file.as_bytes()).unwrap(),
        &signing.bundle(&spec()),
    )
    .unwrap();
}

#[test]
fn the_error_is_the_one_of_the_root_that_got_furthest() {
    let signing = Authority::public_good();
    let other = Authority::public_good();
    let third = Authority::public_good();
    let file = |a: &Authority, b: &Authority| {
        TrustedRoots::parse(
            format!("{}\n{}", a.trusted_root_json(), b.trusted_root_json()).as_bytes(),
        )
        .unwrap()
    };
    let mut wrong_runner = spec();
    wrong_runner
        .identity
        .claims
        .insert(claim::RUNNER_ENVIRONMENT, "self-hosted".to_owned());
    let bundle = signing.bundle(&wrong_runner);

    // a signer error from one root beats a chain error from the other, in either order
    for roots in [file(&signing, &other), file(&other, &signing)] {
        assert_token(check(&roots, &bundle), "bundle_signer");
    }
    // two chain errors: the first root's
    let both_chain = assert_token(check(&file(&other, &third), &bundle), "bundle_chain");
    let first_only = assert_token(check(&roots_of(&other), &bundle), "bundle_chain");
    assert_eq!(both_chain, first_only);
    // two signer errors: the first root's
    let twice = file(&signing, &signing);
    assert_token(check(&twice, &bundle), "bundle_signer");
    // a root that accepts ends the search
    assert!(check(&file(&signing, &other), &signing.bundle(&spec())).is_ok());
}

#[test]
fn trusted_roots_parse_one_document_or_many() {
    let authority = Authority::public_good();
    let value: Value = serde_json::from_str(&authority.trusted_root_json()).unwrap();
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    let roots = TrustedRoots::parse(pretty.as_bytes()).unwrap();
    check(&roots, &authority.bundle(&spec())).unwrap();
    assert_eq!(
        format!("{roots:?}").matches("roots: 1").count(),
        1,
        "{roots:?}"
    );

    let lines = format!(
        "{}\n{}\n\n",
        authority.trusted_root_json(),
        authority.trusted_root_json()
    );
    let roots = TrustedRoots::parse(lines.as_bytes()).unwrap();
    assert!(format!("{roots:?}").contains("roots: 2"));
}

#[test]
fn trusted_roots_that_cannot_be_used_are_refused() {
    let good = Authority::public_good().trusted_root_json();
    for empty in [&b""[..], b"  \n\t\n"] {
        assert_eq!(TrustedRoots::parse(empty).unwrap_err(), RootError::Empty);
    }
    for (bytes, index) in [
        (b"not json".to_vec(), 1),
        (b"{}".to_vec(), 1),
        (b"[]".to_vec(), 1),
        (format!("{good}\n{{\"mediaType\":").into_bytes(), 2),
        (format!("{good} trailing").into_bytes(), 2),
    ] {
        match TrustedRoots::parse(&bytes) {
            Err(RootError::Parse { index: got, detail }) => {
                assert_eq!(got, index);
                assert!(!detail.is_empty() && !detail.contains('\n'));
            }
            other => panic!("{other:?}"),
        }
    }

    // a key window that ends before it starts
    let mut value: Value = serde_json::from_str(&good).unwrap();
    value["tlogs"][0]["publicKey"]["validFor"]["end"] = json!("2026-01-01T00:00:00Z");
    let error = TrustedRoots::parse(format!("{good}\n{value}").as_bytes()).unwrap_err();
    match &error {
        RootError::Unusable { index: 2, detail } => {
            assert!(detail.contains("ends before it starts"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    assert!(error.to_string().contains("trusted root 2 is unusable"));
}

#[test]
fn the_newest_key_of_the_roots_is_reported() {
    let authority = Authority::public_good();
    let minted = TrustedRoots::parse(authority.trusted_root_json().as_bytes()).unwrap();
    let from: jiff::Timestamp = "2026-09-15T00:00:00Z".parse().unwrap();
    assert_eq!(minted.newest_key(), Some(KeyValidity { from, until: None }));

    // the keys of a root that rotate: the newest one's end is shown
    let mut value: Value = serde_json::from_str(&authority.trusted_root_json()).unwrap();
    value["timestampAuthorities"][0]["validFor"] =
        json!({"start": "2026-12-01T00:00:00Z", "end": "2027-03-01T00:00:00Z"});
    let rotating = TrustedRoots::parse(value.to_string().as_bytes()).unwrap();
    assert_eq!(
        rotating.newest_key(),
        Some(KeyValidity {
            from: "2026-12-01T00:00:00Z".parse().unwrap(),
            until: Some("2027-03-01T00:00:00Z".parse().unwrap())
        })
    );

    // keys without a validity window start at the beginning of time
    let mut value: Value = serde_json::from_str(&authority.trusted_root_json()).unwrap();
    for section in ["tlogs", "ctlogs"] {
        value[section][0]["publicKey"]
            .as_object_mut()
            .unwrap()
            .remove("validFor");
    }
    for section in ["certificateAuthorities", "timestampAuthorities"] {
        value[section][0]
            .as_object_mut()
            .unwrap()
            .remove("validFor");
    }
    let unbounded = TrustedRoots::parse(value.to_string().as_bytes()).unwrap();
    assert_eq!(
        unbounded.newest_key(),
        Some(KeyValidity {
            from: jiff::Timestamp::MIN,
            until: None
        })
    );
}

#[test]
fn the_newest_key_comes_from_any_root_of_the_file() {
    let none = r#"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}"#;
    let older = Authority::public_good();
    let mut value: Value = serde_json::from_str(&older.trusted_root_json()).unwrap();
    value["certificateAuthorities"][0]["validFor"] = json!({"start": "2026-09-20T00:00:00Z"});
    value["timestampAuthorities"][0]["validFor"] = json!({"start": "2026-09-20T00:00:00Z"});
    value["ctlogs"][0]["publicKey"]["validFor"] = json!({"start": "2026-09-20T00:00:00Z"});
    value["tlogs"][0]["publicKey"]["validFor"] = json!({"start": "2026-09-20T00:00:00Z"});
    let newer = value.to_string();
    let older = older.trusted_root_json();
    let newest = |files: &[&str]| {
        TrustedRoots::parse(files.join("\n").as_bytes())
            .unwrap()
            .newest_key()
            .map(|k| k.from.to_string())
    };

    assert_eq!(newest(&[none]), None);
    assert_eq!(newest(&[none, none]), None);
    assert_eq!(
        newest(&[none, &older]).as_deref(),
        Some("2026-09-15T00:00:00Z")
    );
    assert_eq!(
        newest(&[&older, none]).as_deref(),
        Some("2026-09-15T00:00:00Z")
    );
    assert_eq!(
        newest(&[&older, &newer]).as_deref(),
        Some("2026-09-20T00:00:00Z")
    );
    assert_eq!(
        newest(&[&newer, &older]).as_deref(),
        Some("2026-09-20T00:00:00Z")
    );
    assert_eq!(
        newest(&[&older, &older]).as_deref(),
        Some("2026-09-15T00:00:00Z")
    );
}

#[test]
fn errors_have_tokens_and_messages() {
    let tokens = [
        (
            VerifyError::Invalid {
                detail: "d".to_owned(),
            },
            "bundle_invalid",
        ),
        (
            VerifyError::Subject {
                detail: "d".to_owned(),
            },
            "bundle_subject",
        ),
        (
            VerifyError::Signer {
                detail: "d".to_owned(),
            },
            "bundle_signer",
        ),
        (
            VerifyError::Chain {
                detail: "d".to_owned(),
            },
            "bundle_chain",
        ),
    ];
    for (error, token) in tokens {
        assert_eq!(error.token(), token);
        assert_eq!(error.detail(), "d");
        assert!(error.to_string().ends_with(": d"), "{error}");
    }
    assert!(RootError::Empty.to_string().contains("no trusted root"));
}

#[test]
fn trusted_roots_can_be_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<TrustedRoots>();
    shared::<VerifyError>();
}

mod real_bundles {
    use super::*;

    const ROOTS: &[u8] = include_bytes!("fixtures/trusted_root.jsonl");
    const HOSTKEEPER: &[u8] = include_bytes!(
        "fixtures/hostkeeper-coordinator-0.1.251-linux-x86_64.image.tar.sigstore.json"
    );
    const KBF: &[u8] = include_bytes!(
        "fixtures/kbf-frontend-image-d494947fb87d9bf78fbf0f6be22eb918c94e3778-linux-x86_64.oci.tar.sigstore.json"
    );
    const HOSTKEEPER_TAR: &str =
        "sha256:14e2eb802e3d092ccdd93a5ea7dbbf1734d0a195918ce33a56e5cbd6c3b4867a";
    const KBF_TAR: &str = "sha256:6c8049239235d56e3df6a3923ad3a232edab984b447843aef090c2cad7932944";
    const HOSTKEEPER_PATTERN: &str = "hostkeeper-coordinator-*-linux-x86_64.image.tar";
    const KBF_PATTERN: &str = "kbf-frontend-image-*-linux-x86_64.oci.tar";

    fn hostkeeper() -> Signer {
        Signer {
            repository: "komira-ai/hostkeeper".to_owned(),
            repository_id: "1443364626".to_owned(),
            workflow: ".github/workflows/artifacts.yml".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            triggers: vec!["push".to_owned()],
        }
    }

    fn kbf() -> Signer {
        Signer {
            repository: "komira-ai/kbf".to_owned(),
            repository_id: "1407971705".to_owned(),
            workflow: ".github/workflows/artifacts.yml".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
            triggers: vec!["push".to_owned()],
        }
    }

    fn roots() -> TrustedRoots {
        TrustedRoots::parse(ROOTS).unwrap()
    }

    fn digest(text: &str) -> Digest {
        Digest::parse(text).unwrap()
    }

    #[test]
    fn the_trusted_root_file_holds_both_roots() {
        let roots = roots();
        assert!(format!("{roots:?}").contains("roots: 2"));
        // GitHub's own instance has the newest key; it has no announced end
        let from: jiff::Timestamp = "2026-06-12T00:00:00Z".parse().unwrap();
        assert_eq!(roots.newest_key(), Some(KeyValidity { from, until: None }));
    }

    #[test]
    fn the_hostkeeper_release_verifies_offline() {
        let verified = run(
            &roots(),
            HOSTKEEPER,
            &digest(HOSTKEEPER_TAR),
            &hostkeeper(),
            HOSTKEEPER_PATTERN,
        )
        .unwrap();
        assert_eq!(
            verified.subject_name,
            "hostkeeper-coordinator-0.1.251-linux-x86_64.image.tar"
        );
        assert_eq!(
            verified.signed_time,
            jiff::Timestamp::from_second(1_794_341_995).unwrap()
        );
    }

    #[test]
    fn the_kbf_release_verifies_offline() {
        let verified = run(&roots(), KBF, &digest(KBF_TAR), &kbf(), KBF_PATTERN).unwrap();
        assert_eq!(
            verified.subject_name,
            "kbf-frontend-image-d494947fb87d9bf78fbf0f6be22eb918c94e3778-linux-x86_64.oci.tar"
        );
        assert_eq!(
            verified.signed_time,
            jiff::Timestamp::from_second(1_793_940_419).unwrap()
        );
    }

    #[test]
    fn real_bundles_are_refused_for_a_wrong_digest_name_or_identity() {
        let roots = roots();
        // the tar changed after signing, or the other release's tar
        assert_token(
            run(
                &roots,
                HOSTKEEPER,
                &digest(KBF_TAR),
                &hostkeeper(),
                HOSTKEEPER_PATTERN,
            ),
            "bundle_subject",
        );
        assert_token(
            run(
                &roots,
                HOSTKEEPER,
                &digest(&format!("sha256:{}", "0".repeat(64))),
                &hostkeeper(),
                HOSTKEEPER_PATTERN,
            ),
            "bundle_subject",
        );
        // another artifact name
        assert_token(
            run(
                &roots,
                HOSTKEEPER,
                &digest(HOSTKEEPER_TAR),
                &hostkeeper(),
                "other-*.tar",
            ),
            "bundle_subject",
        );
        assert_token(
            run(
                &roots,
                HOSTKEEPER,
                &digest(HOSTKEEPER_TAR),
                &hostkeeper(),
                KBF_PATTERN,
            ),
            "bundle_subject",
        );
        // another repository id, repository, workflow, ref or trigger
        let changes: [fn(&mut Signer); 5] = [
            |s| s.repository_id = "1443364627".to_owned(),
            |s| s.repository = "komira-ai/other".to_owned(),
            |s| s.workflow = ".github/workflows/other.yml".to_owned(),
            |s| s.git_ref = "refs/heads/other".to_owned(),
            |s| s.triggers = vec!["release".to_owned()],
        ];
        for change in changes {
            let mut signer = hostkeeper();
            change(&mut signer);
            assert_token(
                run(
                    &roots,
                    HOSTKEEPER,
                    &digest(HOSTKEEPER_TAR),
                    &signer,
                    HOSTKEEPER_PATTERN,
                ),
                "bundle_signer",
            );
        }
        // one release's bundle under the other's signer
        assert_token(
            run(&roots, KBF, &digest(KBF_TAR), &hostkeeper(), KBF_PATTERN),
            "bundle_signer",
        );
    }

    #[test]
    fn a_real_bundle_needs_the_root_of_its_instance() {
        // both are public-good Sigstore bundles: GitHub's own root alone does not know them
        let github_only = ROOTS.split(|b| *b == b'\n').nth(1).unwrap();
        let github = TrustedRoots::parse(github_only).unwrap();
        assert_token(
            run(
                &github,
                HOSTKEEPER,
                &digest(HOSTKEEPER_TAR),
                &hostkeeper(),
                HOSTKEEPER_PATTERN,
            ),
            "bundle_chain",
        );
        let public_good =
            TrustedRoots::parse(ROOTS.split(|b| *b == b'\n').next().unwrap()).unwrap();
        run(
            &public_good,
            HOSTKEEPER,
            &digest(HOSTKEEPER_TAR),
            &hostkeeper(),
            HOSTKEEPER_PATTERN,
        )
        .unwrap();
    }

    #[test]
    fn a_real_bundle_with_an_altered_log_entry_is_refused() {
        let bundle: Value = serde_json::from_slice(HOSTKEEPER).unwrap();
        let altered = edited(&bundle, |b| {
            let entry = &mut b["verificationMaterial"]["tlogEntries"][0];
            entry["integratedTime"] = json!("1794341994");
        });
        let result = run(
            &roots(),
            altered.to_string().as_bytes(),
            &digest(HOSTKEEPER_TAR),
            &hostkeeper(),
            HOSTKEEPER_PATTERN,
        );
        assert_token(result, "bundle_chain");
    }
}
