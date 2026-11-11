# docker-swarm-updater

Deploy a pinned, signature-checked image to a Docker Swarm service when a CI job asks.

docker-swarm-updater runs as a Swarm service on a manager node, behind a proxy that verifies
the caller's OIDC token. For one release of one configured service it downloads the OCI image
tar and its Sigstore bundle from the release's GitHub URLs, verifies the bundle offline
against the signer configured for that service, pushes the image by digest into a local
registry, updates the Swarm service to `<registry>/<repository>@sha256:<digest>`, waits for
Swarm to converge or roll back, and records the outcome. It never rolls back by itself and
never deploys a tag.

The design, including the trust model, the API, every step of a deploy and the test matrix,
is [docs/design.md](docs/design.md).

## Commands

```
docker-swarm-updater serve --config <file> --socket <path> --socket-group <gid> \
    --proxy-uid <uid> --state-dir <dir> --docker <docker socket> \
    [--allow-local-operator] [--ca-file <pem>]
docker-swarm-updater import --config <file> --service <name> --tar <file> \
    --bundle <file> --digest sha256:<hex>
docker-swarm-updater probe http://127.0.0.1:<port>/<path> [--timeout 2s]
docker-swarm-updater probe --unix <socket> /<path>
```

No setting is read from the environment.

## Building and testing

```
cargo build --release
cargo test --workspace
```

The tests need no network, no Docker and no root: Docker, the registry and the release
server are in-process fakes, and the Sigstore chain used by most tests is made by the tests.
`crates/dsu-verify/tests/fixtures` holds real public attestation bundles and the Sigstore
trusted root, verified offline.

CI also runs the tests under branch coverage and holds every crate to at least 99% of lines
and of branches (`cargo xtask coverage`).

## Licence

Apache-2.0.
