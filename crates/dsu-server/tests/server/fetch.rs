//! The fetcher against the fake release server: every `fetch` row of docs/design.md
//! section 6, plus the clock, network and disk implementations it runs on.
use std::sync::Arc;
use std::time::Duration;

use crate::support::{ConnectMode, FakeClock, FakeDisk, FakeNetwork};
use dsu_server::clock::{Clock, SystemClock, with_deadline};
use dsu_server::fetch::{
    CONNECT_TIMEOUT, Disk, FetchError, Fetched, Fetcher, Limits, MAX_REDIRECTS, READ_TIMEOUT,
    SystemDisk, default_roots, roots_from_pem,
};
use dsu_server::net::{Network, SystemNetwork};
use dsu_testkit::release::{ReleaseServer, Route};
use sha2::{Digest as _, Sha256};
use url::Url;

const PATH: &str = "/example-org/app/releases/download/v1/app-1-linux-x86_64.image.tar";
const NO_LIMITS: Limits = Limits {
    max_bytes: None,
    min_free_bytes: 0,
};
const BLOB: &str = "/blob/app.tar";
const OBJECTS: &str = "objects.githubusercontent.com";

fn release_url() -> Url {
    Url::parse(&format!("https://github.com{PATH}")).unwrap()
}

fn redirect(status: u16, location: &str) -> Route {
    Route::Redirect {
        status,
        location: location.to_owned(),
    }
}

fn to_blob() -> Route {
    redirect(302, &format!("https://{OBJECTS}{BLOB}"))
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct World {
    server: ReleaseServer,
    clock: FakeClock,
    network: Arc<FakeNetwork>,
    fetcher: Fetcher,
    dir: tempfile::TempDir,
}

fn redirect_hosts() -> Vec<String> {
    vec![
        OBJECTS.to_owned(),
        "release-assets.githubusercontent.com".to_owned(),
    ]
}

fn fetcher(
    server: &ReleaseServer,
    network: Arc<FakeNetwork>,
    clock: &FakeClock,
    disk: Arc<dyn Disk>,
    hosts: Vec<String>,
) -> Fetcher {
    let roots = roots_from_pem(server.ca_pem().as_bytes()).unwrap();
    Fetcher::new(network, Arc::new(clock.clone()), disk, roots, hosts).unwrap()
}

async fn world(routes: Vec<(&str, Route)>) -> World {
    world_with(
        routes,
        Arc::new(SystemDisk),
        |n| n.allowed(),
        redirect_hosts(),
    )
    .await
}

async fn world_with(
    routes: Vec<(&str, Route)>,
    disk: Arc<dyn Disk>,
    network: impl FnOnce(FakeNetwork) -> FakeNetwork,
    hosts: Vec<String>,
) -> World {
    let server = ReleaseServer::start(routes).await;
    let network = Arc::new(network(FakeNetwork::new(server.port())));
    let clock = FakeClock::new();
    let fetcher = fetcher(&server, network.clone(), &clock, disk, hosts);
    World {
        server,
        clock,
        network,
        fetcher,
        dir: tempfile::tempdir().unwrap(),
    }
}

impl World {
    async fn fetch(&self, limits: &Limits) -> Result<Fetched, FetchError> {
        self.fetcher
            .fetch(&release_url(), self.dir.path(), "image.tar", limits)
            .await
    }

    fn files(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect()
    }
}

#[tokio::test]
async fn downloads_to_a_file_and_hashes_it_without_sending_credentials() {
    let data = body(100_000);
    let w = world(vec![(PATH, Route::File(data.clone()))]).await;
    let got = w.fetch(&NO_LIMITS).await.unwrap();
    assert_eq!(got.path, w.dir.path().join("image.tar"));
    assert_eq!(got.size, 100_000);
    assert_eq!(got.digest.as_str(), digest_of(&data));
    assert_eq!(std::fs::read(&got.path).unwrap(), data);

    let requests = w.server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, PATH);
    let names: Vec<&str> = requests[0]
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(names, ["host", "user-agent"]);
    assert_eq!(requests[0].headers[0].1, "github.com");
    assert_eq!(w.network.resolved(), ["github.com"]);
    assert_eq!(w.network.connects().len(), 1);
}

#[tokio::test]
async fn an_empty_body_is_a_file_of_zero_bytes() {
    let w = world(vec![(PATH, Route::File(Vec::new()))]).await;
    let got = w.fetch(&NO_LIMITS).await.unwrap();
    assert_eq!(got.size, 0);
    assert_eq!(got.digest.as_str(), digest_of(b""));
}

#[tokio::test]
async fn an_unknown_path_is_a_404_and_leaves_no_file() {
    let w = world(vec![]).await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Status { status } if status.as_u16() == 404),
        "{err:?}"
    );
    assert_eq!(err.token(), "fetch_failed");
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn other_statuses_are_fetch_failed() {
    for status in [204, 206, 300, 304, 403, 500] {
        let w = world(vec![(PATH, Route::Status(status))]).await;
        let err = w.fetch(&NO_LIMITS).await.unwrap_err();
        assert!(
            matches!(&err, FetchError::Status { status: s } if s.as_u16() == status),
            "{status}: {err:?}"
        );
        assert_eq!(err.token(), "fetch_failed");
    }
}

#[tokio::test]
async fn a_short_body_is_fetch_failed_and_the_partial_file_is_removed() {
    let w = world(vec![(
        PATH,
        Route::ShortBody {
            body: body(1000),
            declared: 5000,
        },
    )])
    .await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(matches!(err, FetchError::Http(_)), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn a_stalled_read_times_out_on_the_clock_and_removes_the_partial_file() {
    let w = world(vec![(
        PATH,
        Route::Stall {
            sent: body(1000),
            declared: 5000,
        },
    )])
    .await;
    let fetch = w.fetch(&NO_LIMITS);
    let mut fetch = std::pin::pin!(fetch);
    tokio::select! {
        () = w.server.stalled() => {}
        out = &mut fetch => panic!("finished before the stall: {out:?}"),
    }
    let err = w.clock.pump(READ_TIMEOUT, fetch).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Timeout { phase: "read", limit } if limit == READ_TIMEOUT),
        "{err:?}"
    );
    assert_eq!(err.token(), "fetch_failed");
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn a_connect_that_never_completes_times_out_on_the_clock() {
    let w = world_with(
        vec![],
        Arc::new(SystemDisk),
        |n| n.allowed().mode(ConnectMode::Hang),
        redirect_hosts(),
    )
    .await;
    let err = w
        .clock
        .pump(CONNECT_TIMEOUT, w.fetch(&NO_LIMITS))
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Timeout { phase: "connect", limit } if limit == CONNECT_TIMEOUT),
        "{err:?}"
    );
    assert_eq!(err.token(), "fetch_failed");
}

#[tokio::test]
async fn a_redirect_to_an_allowed_host_is_followed_with_that_host_as_the_server_name() {
    for status in [301, 302, 303, 307, 308] {
        let data = body(5000);
        let w = world(vec![
            (
                PATH,
                redirect(status, &format!("https://{OBJECTS}{BLOB}?sig=a%2Fb&x=1")),
            ),
            (&format!("{BLOB}?sig=a%2Fb&x=1"), Route::File(data.clone())),
        ])
        .await;
        let got = w.fetch(&NO_LIMITS).await.unwrap();
        assert_eq!(got.digest.as_str(), digest_of(&data), "{status}");
        let requests = w.server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].path, format!("{BLOB}?sig=a%2Fb&x=1"));
        assert_eq!(
            requests[1].headers[0],
            ("host".to_owned(), OBJECTS.to_owned())
        );
        assert!(requests.iter().all(|r| {
            r.headers
                .iter()
                .all(|(n, _)| n != "authorization" && n != "cookie")
        }));
        assert_eq!(w.network.resolved(), ["github.com", OBJECTS]);
    }
}

#[tokio::test]
async fn five_redirects_are_followed_and_six_are_refused() {
    let chain = |hops: usize| {
        let mut routes: Vec<(String, Route)> = (0..hops)
            .map(|i| {
                let from = if i == 0 {
                    PATH.to_owned()
                } else {
                    format!("/hop/{i}")
                };
                (
                    from,
                    redirect(302, &format!("https://{OBJECTS}/hop/{}", i + 1)),
                )
            })
            .collect();
        routes.push((format!("/hop/{hops}"), Route::File(body(10))));
        routes
    };
    for (hops, ok) in [(MAX_REDIRECTS, true), (MAX_REDIRECTS + 1, false)] {
        let routes = chain(hops);
        let w = world(
            routes
                .iter()
                .map(|(p, r)| (p.as_str(), r.clone()))
                .collect(),
        )
        .await;
        let result = w.fetch(&NO_LIMITS).await;
        if ok {
            assert_eq!(result.unwrap().size, 10, "{hops} hops");
        } else {
            let err = result.unwrap_err();
            assert!(
                matches!(err, FetchError::TooManyRedirects { max: MAX_REDIRECTS }),
                "{hops} hops: {err:?}"
            );
            assert_eq!(err.token(), "url_not_allowed");
            assert!(w.files().is_empty());
            assert_eq!(w.server.requests().len(), MAX_REDIRECTS + 1);
        }
    }
}

#[tokio::test]
async fn a_redirect_loop_is_refused() {
    let w = world(vec![
        (PATH, to_blob()),
        (BLOB, redirect(302, &format!("https://{OBJECTS}{BLOB}"))),
    ])
    .await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(
        matches!(err, FetchError::TooManyRedirects { .. }),
        "{err:?}"
    );
    assert_eq!(err.token(), "url_not_allowed");
    assert_eq!(w.server.requests().len(), MAX_REDIRECTS + 1);
}

#[tokio::test]
async fn redirects_the_rules_refuse_are_url_not_allowed_and_never_connected_to() {
    for location in [
        "https://evil.example/blob",
        "http://objects.githubusercontent.com/blob",
        "https://objects.githubusercontent.com:8443/blob",
        "https://user@objects.githubusercontent.com/blob",
        "https://203.0.113.10/blob",
        // relative to github.com, which is not a redirect host
        "/blob",
        // not a URL at all
        "https://[::1",
    ] {
        let w = world(vec![(PATH, redirect(302, location))]).await;
        let err = w.fetch(&NO_LIMITS).await.unwrap_err();
        assert!(
            matches!(err, FetchError::UrlNotAllowed(_)),
            "{location}: {err:?}"
        );
        assert_eq!(err.token(), "url_not_allowed");
        assert_eq!(w.network.connects().len(), 1, "{location}");
        assert!(w.files().is_empty());
    }
}

#[tokio::test]
async fn a_redirect_without_a_location_is_fetch_failed() {
    let w = world(vec![(PATH, Route::Status(302))]).await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(matches!(err, FetchError::NoLocation { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
}

#[tokio::test]
async fn a_host_that_resolves_to_a_private_address_is_refused_before_connecting() {
    for answer in [
        vec!["127.0.0.1"],
        vec!["100.64.0.1"],
        vec!["10.1.2.3"],
        vec!["169.254.169.254"],
        vec!["::1"],
        vec!["fd00::1"],
        vec!["::ffff:127.0.0.1"],
        // one bad answer among good ones refuses the host
        vec!["203.0.113.10", "127.0.0.1"],
        vec!["127.0.0.1", "203.0.113.10"],
    ] {
        let w = world_with(
            vec![
                (
                    PATH,
                    redirect(302, "https://internal.githubusercontent.com/blob"),
                ),
                (BLOB, Route::File(body(10))),
            ],
            Arc::new(SystemDisk),
            |n| n.allowed().host("internal.githubusercontent.com", &answer),
            vec!["internal.githubusercontent.com".to_owned()],
        )
        .await;
        let err = w.fetch(&NO_LIMITS).await.unwrap_err();
        assert!(
            matches!(err, FetchError::NonPublicAddress { .. }),
            "{answer:?}: {err:?}"
        );
        assert_eq!(err.token(), "url_not_allowed");
        assert_eq!(
            w.network.connects().len(),
            1,
            "{answer:?}: only the first hop was connected"
        );
        assert!(err.to_string().contains("internal.githubusercontent.com"));
    }
}

#[tokio::test]
async fn the_first_url_is_refused_when_it_is_not_https_with_a_domain_name() {
    let w = world(vec![]).await;
    for raw in [
        "http://github.com/x",
        "https://203.0.113.10/x",
        "https://[2001:db8::1]/x",
    ] {
        let err = w
            .fetcher
            .fetch(&Url::parse(raw).unwrap(), w.dir.path(), "f", &NO_LIMITS)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::UrlNotAllowed(_)),
            "{raw}: {err:?}"
        );
    }
    assert!(w.network.resolved().is_empty());
}

#[tokio::test]
async fn a_host_that_is_not_a_valid_server_name_is_fetch_failed() {
    let w = world(vec![]).await;
    let url = Url::parse(&format!("https://{}.example/x", "a".repeat(64))).unwrap();
    let err = w
        .fetcher
        .fetch(&url, w.dir.path(), "f", &NO_LIMITS)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Tls { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
    assert!(w.network.resolved().is_empty());
}

#[tokio::test]
async fn resolution_and_connection_failures_are_fetch_failed() {
    // unknown host
    let w = world_with(vec![], Arc::new(SystemDisk), |n| n, redirect_hosts()).await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(matches!(err, FetchError::Resolve { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
    // no addresses
    let w = world_with(
        vec![],
        Arc::new(SystemDisk),
        |n| n.host("github.com", &[]),
        redirect_hosts(),
    )
    .await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(
        matches!(&err, FetchError::Connect { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
    // every address refuses
    let w = world_with(
        vec![],
        Arc::new(SystemDisk),
        |n| n.host("github.com", &["203.0.113.11", "203.0.113.12"]),
        redirect_hosts(),
    )
    .await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(
        matches!(&err, FetchError::Connect { source, .. } if source.kind() == std::io::ErrorKind::ConnectionRefused),
        "{err:?}"
    );
    assert_eq!(w.network.connects().len(), 2);
}

#[tokio::test]
async fn the_next_address_is_tried_when_the_first_refuses() {
    let w = world_with(
        vec![(PATH, Route::File(body(10)))],
        Arc::new(SystemDisk),
        |n| n.host("github.com", &["203.0.113.11", "203.0.113.10"]),
        redirect_hosts(),
    )
    .await;
    assert_eq!(w.fetch(&NO_LIMITS).await.unwrap().size, 10);
    assert_eq!(w.network.connects().len(), 2);
}

#[tokio::test]
async fn a_certificate_from_another_authority_or_for_another_name_fails_the_handshake() {
    let other = ReleaseServer::start(vec![]).await;
    let w = world(vec![(PATH, Route::File(body(10)))]).await;
    let roots = roots_from_pem(other.ca_pem().as_bytes()).unwrap();
    let untrusting = Fetcher::new(
        w.network.clone(),
        Arc::new(w.clock.clone()),
        Arc::new(SystemDisk),
        roots,
        redirect_hosts(),
    )
    .unwrap();
    let err = untrusting
        .fetch(&release_url(), w.dir.path(), "f", &NO_LIMITS)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Tls { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");

    let w = world_with(
        vec![],
        Arc::new(SystemDisk),
        |n| n.host("wrong.example.net", &["203.0.113.10"]),
        redirect_hosts(),
    )
    .await;
    let url = Url::parse("https://wrong.example.net/x").unwrap();
    let err = w
        .fetcher
        .fetch(&url, w.dir.path(), "f", &NO_LIMITS)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Tls { .. }), "{err:?}");
}

#[tokio::test]
async fn the_size_limit_is_checked_against_content_length_and_the_running_count() {
    for (route, what) in [
        (Route::File(body(100)), "content-length"),
        (Route::Unframed(body(100)), "running count"),
    ] {
        let w = world(vec![(PATH, route.clone())]).await;
        let too_small = Limits {
            max_bytes: Some(99),
            min_free_bytes: 0,
        };
        let err = w.fetch(&too_small).await.unwrap_err();
        assert!(
            matches!(err, FetchError::TooLarge { limit: 99 }),
            "{what}: {err:?}"
        );
        assert_eq!(err.token(), "too_large");
        assert!(w.files().is_empty(), "{what}");

        let exact = Limits {
            max_bytes: Some(100),
            min_free_bytes: 0,
        };
        assert_eq!(w.fetch(&exact).await.unwrap().size, 100, "{what}");
    }
}

#[tokio::test]
async fn a_download_over_the_limit_with_no_content_length_stops_while_streaming() {
    let w = world(vec![(PATH, Route::Unframed(body(2 << 20)))]).await;
    let err = w
        .fetch(&Limits {
            max_bytes: Some(1 << 20),
            min_free_bytes: 0,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::TooLarge { limit } if limit == 1 << 20),
        "{err:?}"
    );
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn the_disk_must_keep_its_minimum_free_space() {
    let limits = |min: u64| Limits {
        max_bytes: None,
        min_free_bytes: min,
    };
    // known length: refused up front, exactly at the boundary
    for (free, min, ok) in [(1000, 2000, false), (2099, 2000, false), (2100, 2000, true)] {
        let disk = Arc::new(FakeDisk::new(free));
        let w = world_with(
            vec![(PATH, Route::File(body(100)))],
            disk.clone(),
            |n| n.allowed(),
            redirect_hosts(),
        )
        .await;
        let result = w.fetch(&limits(min)).await;
        if ok {
            assert_eq!(result.unwrap().size, 100, "free {free}");
        } else {
            let err = result.unwrap_err();
            assert!(
                matches!(err, FetchError::DiskFull { free: f, needed: 2100 } if f == free),
                "{err:?}"
            );
            assert_eq!(err.token(), "fetch_failed");
            assert_eq!(disk.chunks(), 0, "nothing was written");
            assert!(w.files().is_empty());
        }
    }
}

#[tokio::test]
async fn the_free_space_is_checked_again_while_streaming() {
    let size = 2 << 20;
    let disk = Arc::new(FakeDisk::new(1 << 20));
    let w = world_with(
        vec![(PATH, Route::Unframed(body(size)))],
        disk.clone(),
        |n| n.allowed(),
        redirect_hosts(),
    )
    .await;
    let err = w
        .fetch(&Limits {
            max_bytes: None,
            min_free_bytes: 1 << 19,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::DiskFull { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
    assert!(disk.chunks() >= 1);
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn a_write_failing_midway_is_fetch_failed_and_the_partial_file_is_removed() {
    let disk = Arc::new(FakeDisk::new(u64::MAX).failing_at(2));
    let w = world_with(
        vec![(PATH, Route::File(body(2 << 20)))],
        disk.clone(),
        |n| n.allowed(),
        redirect_hosts(),
    )
    .await;
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(
        matches!(&err, FetchError::Write { path, .. } if path.ends_with("image.tar")),
        "{err:?}"
    );
    assert_eq!(err.token(), "fetch_failed");
    assert_eq!(
        disk.chunks(),
        2,
        "the first chunk was written, the second failed"
    );
    assert!(w.files().is_empty());
}

#[tokio::test]
async fn the_free_space_of_a_missing_directory_cannot_be_read() {
    let w = world(vec![(PATH, Route::File(body(10)))]).await;
    let missing = w.dir.path().join("missing");
    let err = w
        .fetcher
        .fetch(&release_url(), &missing, "f", &NO_LIMITS)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::FreeSpace { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
}

#[tokio::test]
async fn a_file_that_cannot_be_created_is_fetch_failed_and_an_existing_file_is_kept() {
    let disk = Arc::new(FakeDisk::new(u64::MAX));
    let w = world_with(
        vec![(PATH, Route::File(body(10)))],
        disk,
        |n| n.allowed(),
        redirect_hosts(),
    )
    .await;
    // the directory does not exist
    let missing = w.dir.path().join("missing");
    let err = w
        .fetcher
        .fetch(&release_url(), &missing, "f", &NO_LIMITS)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Create { .. }), "{err:?}");
    assert_eq!(err.token(), "fetch_failed");
    // the file exists: it is neither overwritten nor removed
    std::fs::write(w.dir.path().join("image.tar"), b"earlier").unwrap();
    let err = w.fetch(&NO_LIMITS).await.unwrap_err();
    assert!(matches!(err, FetchError::Create { .. }), "{err:?}");
    assert_eq!(
        std::fs::read(w.dir.path().join("image.tar")).unwrap(),
        b"earlier"
    );
}

#[test]
fn error_tokens_and_one_line_details() {
    let io = || std::io::Error::other("x");
    let url_error = dsu_core::url::UrlError::Refused {
        url: "u".into(),
        rule: "r",
    };
    let cases: Vec<(FetchError, &str)> = vec![
        (FetchError::UrlNotAllowed(url_error), "url_not_allowed"),
        (
            FetchError::NonPublicAddress {
                host: "h".into(),
                addr: "127.0.0.1".parse().unwrap(),
            },
            "url_not_allowed",
        ),
        (FetchError::TooManyRedirects { max: 5 }, "url_not_allowed"),
        (FetchError::TooLarge { limit: 1 }, "too_large"),
        (FetchError::CaFile("x".into()), "fetch_failed"),
        (
            FetchError::Resolve {
                host: "h".into(),
                source: io(),
            },
            "fetch_failed",
        ),
        (
            FetchError::Connect {
                host: "h".into(),
                source: io(),
            },
            "fetch_failed",
        ),
        (
            FetchError::Tls {
                host: "h".into(),
                source: io(),
            },
            "fetch_failed",
        ),
        (
            FetchError::Timeout {
                phase: "read",
                limit: READ_TIMEOUT,
            },
            "fetch_failed",
        ),
        (FetchError::DiskFull { free: 1, needed: 2 }, "fetch_failed"),
        (
            FetchError::FreeSpace {
                dir: "d".into(),
                source: io(),
            },
            "fetch_failed",
        ),
        (
            FetchError::Create {
                path: "p".into(),
                source: io(),
            },
            "fetch_failed",
        ),
        (
            FetchError::Write {
                path: "p".into(),
                source: io(),
            },
            "fetch_failed",
        ),
    ];
    for (error, token) in cases {
        assert_eq!(error.token(), token, "{error}");
        assert!(!error.to_string().contains('\n'), "{error}");
    }
}

#[tokio::test]
async fn ca_files_replace_the_roots_and_must_hold_a_usable_certificate() {
    let server = ReleaseServer::start(vec![]).await;
    let store = roots_from_pem(server.ca_pem().as_bytes()).unwrap();
    assert_eq!(store.len(), 1);
    let two = format!("{0}{0}", server.ca_pem());
    assert_eq!(roots_from_pem(two.as_bytes()).unwrap().len(), 2);

    let not_pem = "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
    let not_a_cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    for (text, what) in [
        (not_pem, "bad base64"),
        (not_a_cert, "not a certificate"),
        ("", "empty"),
        ("hello", "no pem"),
    ] {
        let err = roots_from_pem(text.as_bytes()).unwrap_err();
        assert!(matches!(err, FetchError::CaFile(_)), "{what}: {err:?}");
        assert_eq!(err.token(), "fetch_failed");
    }
    assert!(!default_roots().is_empty());
    Fetcher::new(
        Arc::new(SystemNetwork),
        Arc::new(SystemClock),
        Arc::new(SystemDisk),
        default_roots(),
        vec![],
    )
    .unwrap();
}

#[tokio::test]
async fn the_system_clock_tells_the_time_and_resolves_zero_length_waits() {
    let clock = SystemClock;
    let floor: jiff::Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
    assert!(clock.now() > floor);
    clock.sleep(Duration::ZERO).await;
    clock.deadline(Duration::ZERO).await;
}

#[tokio::test]
async fn with_deadline_returns_the_work_or_the_timeout() {
    let clock = FakeClock::new();
    // work that is ready wins, even with a deadline that has passed
    clock.advance(Duration::from_secs(5));
    assert_eq!(
        with_deadline(&clock, Duration::ZERO, async { 7 }).await,
        Ok(7)
    );
    // work that never finishes loses to the deadline, which the test moves
    let limit = Duration::from_secs(60);
    let never = with_deadline(&clock, limit, std::future::pending::<()>());
    let err = clock.pump(limit, never).await.unwrap_err();
    assert_eq!(err.limit, limit);
    assert!(err.to_string().contains("60s"));
}

#[tokio::test]
async fn the_fake_clock_moves_only_when_told() {
    let clock = FakeClock::new();
    let start = clock.now();
    clock.sleep(Duration::from_secs(10)).await;
    assert_eq!(clock.now().duration_since(start).as_secs(), 10);
    let deadline = clock.deadline(Duration::from_secs(60));
    clock.wait_pending().await;
    let mut deadline = std::pin::pin!(deadline);
    assert!(futures_poll_once(deadline.as_mut()).await.is_none());
    clock.advance(Duration::from_secs(60));
    deadline.await;
}

/// Polls `f` once; `None` when it is not ready.
async fn futures_poll_once<F: std::future::Future<Output = ()>>(
    mut f: std::pin::Pin<&mut F>,
) -> Option<()> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(f.as_mut().poll(cx).is_ready().then_some(())))
        .await
}

#[tokio::test]
async fn the_system_network_resolves_literals_and_connects() {
    let net = SystemNetwork;
    assert_eq!(
        net.resolve("127.0.0.1").await.unwrap(),
        ["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted, connected) = tokio::join!(listener.accept(), net.connect(addr));
    accepted.unwrap();
    assert_eq!(connected.unwrap().peer_addr().unwrap(), addr);
}

#[tokio::test]
async fn the_system_disk_reports_free_space_and_writes() {
    let dir = tempfile::tempdir().unwrap();
    assert!(SystemDisk.free_bytes(dir.path()).unwrap() > 0);
    assert!(SystemDisk.free_bytes(&dir.path().join("missing")).is_err());
    let mut file = tokio::fs::File::create(dir.path().join("f")).await.unwrap();
    SystemDisk.write(&mut file, b"abc").await.unwrap();
    tokio::io::AsyncWriteExt::flush(&mut file).await.unwrap();
    assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), b"abc");
}
