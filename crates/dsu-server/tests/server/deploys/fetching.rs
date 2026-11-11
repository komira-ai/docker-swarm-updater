//! Deploy rows for the fetch, bundle and tar steps: what each refusal ends in.

use crate::harness::*;
use crate::support::{FakeDisk, FakeNetwork};
use dsu_core::ids::Digest;
use dsu_core::record::{ErrorToken, Phase, State};
use dsu_server::fetch::READ_TIMEOUT;
use dsu_testkit::mint::{Authority, Evidence, Identity, Spec, claim, signed_at};
use dsu_testkit::oci::{Flaw, OciImage};
use dsu_testkit::registry::Mode;
use dsu_testkit::release::Route;
use serde_json::json;

use super::*;

// fetch rows

#[tokio::test]
async fn fetch_rows_end_in_failed_records_and_leave_no_files() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let mut missing_image = Rel::new(a, "app", "a");
        missing_image.image_route = Some(Route::Status(404));
        let mut missing_bundle = Rel::new(a, "app", "b");
        missing_bundle.bundle_route = Some(Route::Status(404));
        let mut elsewhere = Rel::new(a, "app", "c");
        elsewhere.image_route = Some(Route::Redirect {
            status: 302,
            location: "https://evil.example/app.tar".into(),
        });
        let mut big_bundle = Rel::new(a, "web", "a");
        big_bundle.bundle_route = Some(Route::File(vec![0; 1024 * 1024 + 1]));
        let mut big_image = Rel::new(a, "web", "b");
        big_image.image_route = Some(Route::File(vec![0; 1024 * 1024 + 1]));
        vec![
            missing_image,
            missing_bundle,
            elsewhere,
            big_bundle,
            big_image,
        ]
    })
    .await;
    let u = w.updater().await;
    let expected = [
        ErrorToken::FetchFailed,
        ErrorToken::FetchFailed,
        ErrorToken::UrlNotAllowed,
        ErrorToken::TooLarge,
        ErrorToken::TooLarge,
    ];
    for (rel, token) in rels.iter().zip(expected) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.phase, Phase::Done);
        assert_eq!(record.steps.last().unwrap().phase, Phase::Fetching);
        // The downloaded files are removed, and the digest is not blocked.
        assert!(w.downloads().is_empty());
        assert!(
            !service_state(&u, rel.service)
                .await
                .is_failed(&rel.digest())
        );
    }
    // Nothing reached the registry or Swarm.
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

// bundle rows

#[tokio::test]
async fn a_bundle_of_another_workflow_fails_and_blocks_the_digest_until_the_operator_clears_it() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let image = OciImage::new("app-a").build();
        let mut signer = service_config("app").signer;
        signer.workflow = ".github/workflows/other.yml".into();
        let bad = Rel::made(a, "app", "a", "v1", image.clone(), |spec| {
            spec.identity = Identity::for_signer(&signer, "push");
        });
        let good = Rel::made(a, "app", "a", "v2", image, |_| {});
        vec![bad, good]
    })
    .await;
    let (bad, good) = (&rels[0], &rels[1]);
    let u = w.updater().await;
    let record = run(&u, bad).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::BundleSigner))
    );
    assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
    assert!(service_state(&u, "app").await.is_failed(&bad.digest()));

    // The same digest is refused, from either release, until the operator clears it.
    let retry = post(&u, good).await;
    assert_eq!(
        (retry.status, retry.error().as_str()),
        (409, "previously_failed")
    );
    let cleared = u
        .as_operator(
            "DELETE",
            &format!("/v1/services/app/failed/{}", good.digest()),
            b"",
        )
        .await;
    assert_eq!(cleared.status, 204);
    let record = run(&u, good).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(w.registry.manifest("app", &good.digest()).is_some());
}

#[tokio::test]
async fn a_bundle_with_only_a_timestamp_converges_and_one_with_no_time_fails() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let timestamp = Rel::made(
            a,
            "app",
            "a",
            "v1",
            OciImage::new("app-a").build(),
            |spec| spec.evidence = Evidence::Timestamp,
        );
        let neither = Rel::made(
            a,
            "app",
            "b",
            "v1",
            OciImage::new("app-b").build(),
            |spec| spec.evidence = Evidence::Neither,
        );
        vec![timestamp, neither]
    })
    .await;
    let u = w.updater().await;
    let record = run(&u, &rels[0]).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(record.signed_time, Some(signed_at()));
    let record = run(&u, &rels[1]).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::BundleChain))
    );
    assert!(service_state(&u, "app").await.is_failed(&rels[1].digest()));
}

#[tokio::test]
async fn a_tar_of_another_digest_fails_without_blocking_the_asked_digest() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    let asked = Digest::from_sha256([9; 32]);
    let body = rel.body_with(|b| b["image_digest"] = json!(asked));
    let reply = post_body(&u, &rel, body.clone()).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::DigestMismatch))
    );
    assert!(service_state(&u, "app").await.failed.is_empty());
    // The retry runs (and fails the same way); it is not refused.
    let retry = post_body(&u, &rel, body).await;
    assert_eq!(retry.status, 202);
    finished(&u.app, &deploy_id(&retry)).await;
}

// tar rows

#[tokio::test]
async fn tar_rows_end_in_failed_records_and_block_their_digest() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let other_platform = OciImage::new("app-a").platform("linux", "arm64").build();
        let missing_blob = OciImage::new("app-b").flaw(Flaw::MissingBlob).build();
        vec![
            Rel::made(a, "app", "a", "v1", other_platform, |_| {}),
            Rel::made(a, "app", "b", "v1", missing_blob, |_| {}),
        ]
    })
    .await;
    let u = w.updater().await;
    for (rel, token) in rels
        .iter()
        .zip([ErrorToken::PlatformMismatch, ErrorToken::TarInvalid])
    {
        let record = run(&u, rel).await;
        assert_eq!(outcome(&record), (State::Failed, Some(token)));
        assert!(service_state(&u, "app").await.is_failed(&rel.digest()));
    }
    assert!(w.registry.events().is_empty());
}

// the fetch row, one release per case: each ends in the record the table names

/// A world with one release of `app` as `build` makes it. The updater reaches the release
/// server through `network` (the allowed hosts resolve to the documentation address, then
/// `network` may change that) and writes through `disk`; the config is the text `config`
/// returns for the harness config.
async fn fetch_world(
    build: impl FnOnce(&mut Rel),
    network: impl FnOnce(FakeNetwork) -> FakeNetwork,
    disk: std::sync::Arc<dyn dsu_server::fetch::Disk>,
    config: impl FnOnce(String) -> String,
) -> (World, Updater, Rel) {
    let (w, rel) = World::one(|a| {
        let mut rel = Rel::new(a, "app", "a");
        build(&mut rel);
        rel
    })
    .await;
    let text = std::fs::read_to_string(&w.env.config_path).unwrap();
    std::fs::write(&w.env.config_path, config(text)).unwrap();
    let options = Options {
        network: std::sync::Arc::new(network(FakeNetwork::new(w.server.port()).allowed())),
        disk,
        ..w.options()
    };
    let u = Updater::start(&w.env, options).await;
    (w, u, rel)
}

/// A redirect to the allowed host `objects.githubusercontent.com` at `path`.
fn redirect_to(path: &str) -> Route {
    Route::Redirect {
        status: 302,
        location: format!("https://objects.githubusercontent.com{path}"),
    }
}

/// What a deploy that ended in the fetching phase leaves: no files, no failed digest, and
/// nothing sent to the registry or Swarm.
async fn assert_refused_before_the_registry(w: &World, u: &Updater, rel: &Rel) {
    assert!(w.downloads().is_empty());
    assert!(!service_state(u, "app").await.is_failed(&rel.digest()));
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

#[tokio::test]
async fn fetch_rows_a_short_body_and_a_redirect_to_an_allowed_host() {
    // A short body: fetch_failed.
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(Route::ShortBody {
                body: rel.image.tar[..100].to_vec(),
                declared: rel.image.tar.len(),
            })
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert_refused_before_the_registry(&w, &u, &rel).await;

    // A redirect to an allowed host is followed: converged.
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(redirect_to("/blob/app.tar"));
            rel.extra = vec![("/blob/app.tar".into(), Route::File(rel.image.tar.clone()))];
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(w.registry.manifest("app", &rel.digest()).is_some());
    assert!(
        w.server
            .requests()
            .iter()
            .any(|r| r.path == "/blob/app.tar")
    );
}

#[tokio::test]
async fn fetch_rows_a_stalled_read_ends_on_the_clock() {
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(Route::Stall {
                sent: rel.image.tar[..100].to_vec(),
                declared: rel.image.tar.len(),
            })
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let id = deploy_id(&post(&u, &rel).await);
    w.server.stalled().await;
    let record = w.env.clock.pump(READ_TIMEOUT, finished(&u.app, &id)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.contains("read"));
    assert_refused_before_the_registry(&w, &u, &rel).await;
}

#[tokio::test]
async fn fetch_rows_redirects_the_rules_refuse_are_url_not_allowed() {
    // To `http`, to a host that resolves to loopback, to a shared address, a loop, and six
    // hops; five hops are followed.
    let hops = |n: usize| {
        move |rel: &mut Rel| {
            rel.image_route = Some(redirect_to("/hop/1"));
            rel.extra = (1..=n)
                .map(|i| {
                    let route = if i == n {
                        Route::File(rel.image.tar.clone())
                    } else {
                        redirect_to(&format!("/hop/{}", i + 1))
                    };
                    (format!("/hop/{i}"), route)
                })
                .collect();
        }
    };
    type Build = Box<dyn FnOnce(&mut Rel)>;
    type Net = fn(FakeNetwork) -> FakeNetwork;
    let cases: Vec<(&str, Build, Net)> = vec![
        (
            "http",
            Box::new(|rel| {
                rel.image_route = Some(Route::Redirect {
                    status: 302,
                    location: "http://objects.githubusercontent.com/x".into(),
                })
            }),
            |n| n,
        ),
        (
            "loopback",
            Box::new(|rel| rel.image_route = Some(redirect_to("/blob"))),
            |n| n.host("objects.githubusercontent.com", &["127.0.0.1"]),
        ),
        (
            "shared address",
            Box::new(|rel| rel.image_route = Some(redirect_to("/blob"))),
            |n| n.host("objects.githubusercontent.com", &["100.64.0.1"]),
        ),
        (
            "a loop",
            Box::new(|rel| {
                rel.image_route = Some(redirect_to("/loop"));
                rel.extra = vec![("/loop".into(), redirect_to("/loop"))];
            }),
            |n| n,
        ),
        ("six hops", Box::new(hops(6)), |n| n),
    ];
    for (what, build, network) in cases {
        let (w, u, rel) = fetch_world(
            build,
            network,
            std::sync::Arc::new(dsu_server::fetch::SystemDisk),
            |t| t,
        )
        .await;
        let record = run(&u, &rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(ErrorToken::UrlNotAllowed)),
            "{what}"
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Fetching);
        assert_refused_before_the_registry(&w, &u, &rel).await;
    }
    // Five hops are the most that are followed.
    let (w, u, rel) = fetch_world(
        hops(5),
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    assert_eq!(run(&u, &rel).await.state, State::Converged);
    assert!(w.registry.manifest("app", &rel.digest()).is_some());
}

#[tokio::test]
async fn fetch_rows_a_disk_below_min_free_bytes_and_a_write_failing_midway() {
    const MIN: u64 = 1_000_000;
    let raised = |t: String| t.replace("min_free_bytes = 0", &format!("min_free_bytes = {MIN}"));
    // The disk keeps `MIN` bytes free after the bundle and the tar, exactly: the deploy
    // converges; one byte less and it is fetch_failed.
    for (short_by, want) in [
        (0, (State::Converged, None)),
        (1, (State::Failed, Some(ErrorToken::FetchFailed))),
    ] {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let free = MIN + (rel.bundle.len() + rel.image.tar.len()) as u64 - short_by;
        std::fs::write(
            &w.env.config_path,
            raised(std::fs::read_to_string(&w.env.config_path).unwrap()),
        )
        .unwrap();
        let u = Updater::start(
            &w.env,
            Options {
                disk: std::sync::Arc::new(FakeDisk::new(free)),
                ..w.options()
            },
        )
        .await;
        let record = run(&u, &rel).await;
        assert_eq!(outcome(&record), want, "short by {short_by}");
        if short_by == 1 {
            assert!(record.error.unwrap().detail.contains("disk"));
            assert_refused_before_the_registry(&w, &u, &rel).await;
        }
    }
    // A write that fails in the middle of the tar: fetch_failed, and no partial file.
    let disk = std::sync::Arc::new(FakeDisk::new(u64::MAX).failing_at(4));
    let (w, u, rel) = fetch_world(
        |rel| rel.image_route = Some(Route::File(vec![7; 2 << 20])),
        |n| n,
        disk.clone(),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.contains("the disk failed"));
    assert_eq!(disk.chunks(), 4);
    assert_refused_before_the_registry(&w, &u, &rel).await;
}

// the bundle row, one release per case

#[tokio::test]
async fn bundle_rows_end_in_failed_records_and_block_the_digest() {
    let signer = || service_config("app").signer;
    let signed_by = |edit: fn(&mut dsu_core::config::Signer)| {
        move |spec: &mut Spec| {
            let mut signer = signer();
            edit(&mut signer);
            spec.identity = Identity::for_signer(&signer, "push");
        }
    };
    type Edit = Box<dyn FnOnce(&mut Spec)>;
    let cases: Vec<(&str, ErrorToken, Edit)> = vec![
        (
            "tar changed after signing",
            ErrorToken::BundleSubject,
            Box::new(|spec| spec.subjects[0].sha256 = Digest::from_sha256([7; 32]).hex().into()),
        ),
        (
            "a valid bundle of another artifact of the same release",
            ErrorToken::BundleSubject,
            Box::new(|spec| spec.subjects[0].name = "other-1.0-linux-x86_64.image.tar".into()),
        ),
        (
            "another workflow",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| {
                s.workflow = ".github/workflows/other.yml".into()
            })),
        ),
        (
            "another ref",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| s.git_ref = "refs/heads/feature".into())),
        ),
        (
            "another repository id",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| s.repository_id = "4242".into())),
        ),
        (
            "another trigger",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity = Identity::for_signer(&service_config("app").signer, "pull_request")
            }),
        ),
        (
            "a self-hosted runner",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity
                    .claims
                    .insert(claim::RUNNER_ENVIRONMENT, "self-hosted".into());
            }),
        ),
        (
            "a run of another repository",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity.claims.insert(
                    claim::RUN_INVOCATION_URI,
                    "https://github.com/example-org/other/actions/runs/7".into(),
                );
            }),
        ),
        (
            "an altered log entry",
            ErrorToken::BundleChain,
            Box::new(|spec| spec.evidence = Evidence::AlteredLog),
        ),
        (
            "neither a log entry nor a timestamp",
            ErrorToken::BundleChain,
            Box::new(|spec| spec.evidence = Evidence::Neither),
        ),
    ];
    let count = cases.len() + 2;
    let (w, rels) = World::new(Mode::Normal, |a| {
        let mut rels: Vec<Rel> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (_, _, edit))| {
                let label = format!("c{i}");
                let image = OciImage::new(&format!("app-{label}")).build();
                Rel::made(a, "app", &label, "v1", image, edit)
            })
            .collect();
        // Not a Sigstore bundle at all, and a chain from another root.
        let mut not_json = Rel::new(a, "app", "j1");
        not_json.bundle_route = Some(Route::File(b"not json".to_vec()));
        rels.push(not_json);
        let image = OciImage::new("app-j2").build();
        rels.push(Rel::made(
            &Authority::public_good(),
            "app",
            "j2",
            "v1",
            image,
            |_| {},
        ));
        rels
    })
    .await;
    assert_eq!(rels.len(), count);
    let wanted: Vec<ErrorToken> = [
        ErrorToken::BundleSubject,
        ErrorToken::BundleSubject,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleChain,
        ErrorToken::BundleChain,
        ErrorToken::BundleInvalid,
        ErrorToken::BundleChain,
    ]
    .into();
    let u = w.updater().await;
    for (rel, token) in rels.iter().zip(wanted) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
        // Found after `index.json` named the digest: it is blocked.
        assert!(
            service_state(&u, "app").await.is_failed(&rel.digest()),
            "{}",
            rel.file
        );
        assert!(w.downloads().is_empty());
    }
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

#[tokio::test]
async fn tar_rows_a_wrong_index_two_manifests_and_a_mis_hashed_blob() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        [
            ("a", Flaw::IndexDigestDiffers),
            ("b", Flaw::TwoManifests),
            ("c", Flaw::MisHashedBlob),
        ]
        .into_iter()
        .map(|(label, flaw)| {
            let image = OciImage::new(&format!("app-{label}")).flaw(flaw).build();
            Rel::made(a, "app", label, "v1", image, |_| {})
        })
        .collect()
    })
    .await;
    let u = w.updater().await;
    // `digest_mismatch` and `tar_invalid` for two manifests are found before the digest is
    // known to be the tar's, so they do not block it; a mis-hashed blob is found after.
    let wanted = [
        (ErrorToken::DigestMismatch, false),
        (ErrorToken::TarInvalid, false),
        (ErrorToken::TarInvalid, true),
    ];
    for (rel, (token, blocked)) in rels.iter().zip(wanted) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
        assert_eq!(
            service_state(&u, "app").await.is_failed(&rel.digest()),
            blocked,
            "{}",
            rel.file
        );
    }
    assert!(w.registry.events().is_empty());
}
