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

## Releases

Each push to `main` makes a release, `v<major>.<minor>.<commits on main>`, built and signed by
[`.github/workflows/artifacts.yml`](.github/workflows/artifacts.yml), unless a newer push
supersedes it before its run starts. For `linux-x86_64` and `linux-arm64` it holds:

| file | what it is |
|---|---|
| `docker-swarm-updater-<version>-<platform>` | the static binary (musl, no program interpreter) |
| `docker-swarm-updater-<version>-<platform>.image.tar` | the container image, an OCI image layout: `FROM scratch`, the binary at `/docker-swarm-updater` as the entrypoint, user `65532:65532` unless the service names one; `docker load` reads it too |
| `<file>.sigstore.json` | the provenance attestation bundle of each file above |
| `SHA256SUMS` | the SHA-256 of the four files |

The signer of every bundle is `.github/workflows/artifacts.yml` of this repository on
`refs/heads/main`, started by `push`; that is the `signer` to configure for this service. The
image's manifest digest (the `image_digest` of a deploy) is the one entry of the tar's
`index.json`. Before anything is signed, the workflow checks that the binary is static and
prints the version, that rebuilding it gives the same bytes, that the image written twice is
the same bytes, and that the image loads into Docker and runs.

After the release is published, the same workflow deploys it to the service
`docker-swarm-updater` through the reusable workflow below, while the repository variables
`CP_DEPLOY_ENDPOINT` (the deploy front) and `CP_DEPLOY_TAILSCALE_TAGS` (the tags of the job's
tailnet node) are set; `CP_DEPLOY_AUDIENCE`, `CP_DEPLOY_TAILSCALE_CLIENT_ID` and
`CP_DEPLOY_TAILSCALE_AUDIENCE` give the rest. With either unset or empty, the deploy jobs are
skipped.

The updater's own health check, in its service's `healthcheck.test`:
`["CMD", "/docker-swarm-updater", "probe", "--unix", "<its socket>", "/v1/health"]`.

## Deploying from a GitHub workflow

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) is a reusable workflow: a release
job calls it, pinned by commit, to deploy one release of one service and wait for the outcome.

```yaml
jobs:
  deploy:
    needs: [release]
    permissions:
      id-token: write
    uses: komira-ai/docker-swarm-updater/.github/workflows/deploy.yml@<40-hex commit>
    with:
      service: app
      version: 1.4.2
      image-digest: sha256:<64 hex>
      image-url: https://github.com/<owner>/<repo>/releases/download/<tag>/<image>.tar
      bundle-url: https://github.com/<owner>/<repo>/releases/download/<tag>/<image>.tar.sigstore.json
      endpoint: ${{ vars.DEPLOY_ENDPOINT }}
      audience: ${{ vars.DEPLOY_AUDIENCE }}
      environment: production
```

| input | default | meaning |
|---|---|---|
| `service` | | the configured service (the `{service}` of the API) |
| `version` | | free text for the record and the log, at most 128 bytes |
| `image-digest`, `image-url`, `bundle-url` | | the deploy request of [docs/design.md](docs/design.md) section 2.2 |
| `signer-repository`, `signer-workflow`, `signer-ref` | the calling repository, `.github/workflows/artifacts.yml`, `refs/heads/main` | the signer the request states; the updater checks it against its config |
| `endpoint` | | the proxy in front of the updater, `http[s]://host[:port]` |
| `audience` | | the audience of every OIDC token, as the proxy expects it |
| `environment` | | the calling repository's environment the job runs in |
| `wait-minutes` | 60 | how long to wait for a final state; 0 waits however long it takes |
| `tailscale-oauth-client-id`, `tailscale-audience`, `tailscale-tags` | empty | when the client id is set, the job first joins that tailnet as an ephemeral node with that Tailscale workload-identity client and those tags; with the client id set and the audience or the tags empty, the job fails before the join, in a step whose name names the empty input |

The job runs in the calling repository's environment, so that repository's environment rules
apply and the token's `environment` claim names it; restrict the environment's deployment
branches to the signing branch. The proxy and the updater check the token's claims, the updater
checks the release's attestation against its configured signer and refuses a release older than
the running one, and Swarm rolls back an update whose new task fails its health check. The
caller's workflow must run on the signing branch (a `push`, or a `workflow_run` of its release
workflow there), not on a `release` event, because the token's `ref` claim is the triggering
ref.

The job builds its client, [`dsu-deploy`](crates/dsu-deploy), from the workflow's own commit,
asks GitHub for a new OIDC token for every request, sends Deploy, then asks for the deploy's
status every 10 s, retrying while the proxy answers 503 or cannot be reached. It passes when
the deploy ends `converged`, fails with the record's error for any other final state, and fails
with "deploy `<id>` still running; it continues" when `wait-minutes` pass.

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
