# docker-swarm-updater: deploy a pinned, signature-checked image to a Docker Swarm service when a CI job asks

Status: design.

**What it is.** A small program that runs as a Docker Swarm service on a manager node. A CI job (GitHub Actions) asks it to deploy one
release of one service. It downloads the release's OCI image tar and its Sigstore bundle from the release's public URLs, verifies the
bundle offline against the signer identity configured for that service, pushes the image by digest into a registry next to it,
updates the Swarm service to `<registry>/<name>@sha256:<digest>` through the Docker API, waits until Swarm says the update converged or
rolled back, and reports.

**What it is not.**

- It does not authenticate callers. It must sit behind a proxy that verified the caller's OIDC token (section 1), and it refuses a
  request that did not come from that proxy's process.
- It does not build images, follow tags, poll registries or decide when to deploy. A deploy happens only when a caller asks for one
  digest.
- It does not replace Swarm's rolling update. The service's own `update_config` (order, health check, `failure_action: rollback`,
  monitor window) decides how the update runs. docker-swarm-updater starts the update, watches it, and never rolls back by itself.
- It does not run Kubernetes, Compose without Swarm, Windows or macOS. Linux, Docker Engine in swarm mode, one replica on a manager.

Labels: **[E]** upstream documentation (page named); **[I]** inference or proposal, proven by the tests of section 6 or the first
real use.

## 0. Prior art

| project | what it does | what it lacks for this use |
|---|---|---|
| Portainer service webhooks | a secret URL re-pulls a service's tag | the URL is the only secret; tags; a whole management product |
| docker-deploy-webhook, docker-swarm-redeploy | Docker Hub webhook payloads update a service | shared tokens, hub payloads, no signature check; unmaintained |
| kapten, cioban, shepherd | poll a tag and update the service | follow tags; no caller identity; no signature check |
| `docker stack deploy` GitHub Actions | the runner deploys over SSH or the Docker API | the runner holds the Docker API (root on the node) through a stored secret |
| Flux `generic-oidc` receiver | verifies an OIDC token and triggers a reconcile | Kubernetes only; no pinned, attested digest |

None verifies a GitHub OIDC token and deploys a pinned, attested digest [I] (each project's documentation, read page by page; not a
proof of absence).

## 1. Trust model

```
CI job ──OIDC bearer token──> fronting proxy (verifies the token; exact claims per route)
          ──HTTP over a Unix socket, verified claims in one header──> docker-swarm-updater ──> Docker API (socket)
                                                                                         └──> local registry
```

- **The proxy authenticates.** It verifies the token's signature against the issuer's keys, its issuer, audience, expiry and
  not-before, and it allows each route only to exact claim values. It removes any client-sent claims header and sets it from the verified
  payload. Any proxy that does this works; section 1.1 shows Envoy.
- **docker-swarm-updater authorises again.** It reads the claims header and maps the claims to the services they may act on from its
  own config (section 2.3), on every route: Deploy, Status and List. The two checks are independent: a mistake in one refuses; it never
  grants. The token's audience is a guard against tokens minted for another receiver, not an access control: any workflow can ask for any
  audience.
- **Only the proxy's process can call it.** It listens on one Unix socket and nothing else; the socket's directory and mode let only
  `--socket-group` (and root) open it. On every connection it reads the peer's uid with `SO_PEERCRED`, as the kernel maps it into
  the updater's user namespace; the peer's pid is never consulted (it is 0 for a client outside the updater's pid namespace, such as
  root on the host of the updater's container):
  - a request **with** the claims header is accepted only from a peer whose uid is `--proxy-uid`;
  - a request **without** it is accepted only from uid 0, and only when `--allow-local-operator` is given; the record names
    `operator (uid 0)`. Root on the node already controls Docker, so this grants nothing new;
  - every other combination is refused 401 `bad_peer` (a headerless request from a uid other than 0 included). A claims header from
    uid 0 is refused: the operator path never carries claims. The one exception is `GET /v1/health`, answered for any peer that can
    open the socket, with or without claims (it carries no data).
  - a connection whose peer's credentials cannot be read is still answered: health as above, every other request 401 `bad_peer`
    with the reason. Every request refused 401 or 403 is logged on stderr with the method, the path, the peer's uid, gid and pid, and
    the answer, so a refused peer is never a silent close.
  - `--proxy-uid 0` is refused at start. The node must have no other account with the proxy's uid; the updater cannot check that.
- **One token per request.** A token's `jti` is accepted once, on any route. The caller asks for a new token for every request (a local
  call on a GitHub runner). Accepted ids are kept in the state directory until their `exp` passes, so a restart does not forget them. A
  request refused after its claims were read still spends its `jti`.

### 1.1 Envoy as the fronting proxy

A sketch (each field is in Envoy's HTTP connection manager, `jwt_authn`, `rbac` and `header_mutation` references [E]):

```yaml
normalize_path: true
merge_slashes: true
path_with_escaped_slashes_action: REJECT_REQUEST
http_filters:
- name: envoy.filters.http.header_mutation
  typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation,
                  mutations: { request_mutations: [ { remove: x-dsu-claims } ] } }
- name: envoy.filters.http.jwt_authn
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
    providers:
      github:
        issuer: https://token.actions.githubusercontent.com
        audiences: [ <your audience> ]
        remote_jwks: { http_uri: { uri: <jwks_uri of the issuer's discovery document>, cluster: github_oidc, timeout: 5s },
                       cache_duration: 600s, async_fetch: { fast_listener: false } }
        forward: false
        forward_payload_header: x-dsu-claims
        payload_in_metadata: github
    rules: [ { match: { prefix: / }, requires: { provider_name: github } } ]
- name: envoy.filters.http.rbac        # deny unless the route's RBACPerRoute allows
  typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC, rules: { action: ALLOW, policies: {} } }
- name: envoy.filters.http.router
```

Routes match an exact `:method` and an exact `path` (Deploy, List), or a `safe_regex` on the `{id}` segment only (Status); a deploy
route's policy is an `and_ids` of `sourced_metadata` exact matches on
`repository`, `repository_id`, `job_workflow_ref`, `ref`, `environment` and `runner_environment`; the read routes' policy is the
`or_ids` of every deploy policy. A request that matches no route is refused by `jwt_authn` (401) or RBAC (403) before the router sees it.
The upstream cluster is a `pipe` address: the updater's socket. Request bodies are capped (16 KiB).

### 1.2 Why the updater does not verify tokens itself

One place that verifies signatures is easier to keep right than two, and the proxy already does it for other routes. The updater still
checks the peer, the claims against its config and replays, so a proxy misconfigured to pass every request through still cannot deploy a
service whose config does not name the caller, nor a release the configured signer did not make.

## 2. API

HTTP/1.1, JSON bodies, over the Unix socket. Every response has `content-type: application/json`; every error is
`{"error": "<token>", "detail": "<one line>"}`. Times are RFC 3339 UTC.

The request target is matched byte for byte, before any decoding, against the routes below: `{service}` is `[a-z0-9-]{1,63}`, `{id}` is
`d-[a-z2-7]{26}`, `{digest}` is `sha256:[0-9a-f]{64}`. A `%`, `..`, `//`, a trailing slash, an upper-case letter or a query string is 404
`not_found`; a known path with another method is 405. A body over 16 KiB is 413. A connection idle for 30 s is closed.

### 2.1 Endpoints

| method and path | does | who | answers |
|---|---|---|---|
| `POST /v1/services/{service}/deploys` | Deploy | a caller of `{service}`, or the local operator (any service; the record's caller is `operator (uid 0)`) | 202 started; 200 the same (service, digest) already converged or running (that record); 400 `bad_request`; 401 `no_claims`, `bad_peer`, `expired`, `replayed`; 403 `not_allowed`, `signer_mismatch`, `url_not_allowed`; 404 `unknown_service`; 409 `busy` (another digest of this service is deploying; its id in `detail`), `previously_failed`, `self_update_busy` |
| `GET /v1/deploys/{id}` | Status | a caller of the record's service, or the local operator | 200 the record; 401 as Deploy; 404 `unknown_deploy` (also when the caller may not see it) |
| `GET /v1/services` | List | any configured caller, or the local operator | 401 as Deploy; 200 the services that caller may act on (all for the operator): Swarm service name, running digests from Swarm, update state, last deploy id, failed digests, the signed-time floor |
| `DELETE /v1/services/{service}/failed/{digest}` | clear one failed digest | local operator | 204; 403 `not_allowed`; 404 |
| `GET /v1/health` | health of the updater itself | any peer that can open the socket, no claims | 200 `{"ok": true}` once the config loaded, the state directory is writable and the Docker API answered; 503 otherwise |

`{service}` is a name from the config, never a Swarm service name the caller picks. A deploy found by verification to be bad is not a
4xx: it is a record that ends `failed` (section 2.2), because the fault is found after the download.

### 2.2 Deploy request and record

Request body:

```json
{
  "image_digest": "sha256:<64 hex>",
  "image_url": "https://github.com/<owner>/<repo>/releases/download/<tag>/<image>.tar",
  "bundle_url": "https://github.com/<owner>/<repo>/releases/download/<tag>/<image>.tar.sigstore.json",
  "signer": { "repository": "<owner>/<repo>", "workflow": ".github/workflows/<file>.yml", "ref": "refs/heads/main" },
  "version": "<free text, at most 128 bytes, for the record and the log>",
  "allow_older": false
}
```

- `image_digest` is the manifest digest the caller expects (the single entry of the tar's `index.json` for a one-platform tar).
- `signer` is optional. When present it must equal the configured signer on the three fields it carries, or the request is refused
  `signer_mismatch`; `repository_id` and the other identity checks come from the config only. Verification always uses the configured
  signer, so a caller can never widen it.
- `allow_older` is accepted only from the local operator (section 3.3 step 5); from a caller it is 400.
- Unknown fields are refused (`bad_request`), so a misspelt field never silently means "absent".

Record (`GET /v1/deploys/{id}`):

```json
{
  "id": "d-<26 base32>",
  "service": "app", "swarm_service": "app_server",
  "image_digest": "sha256:...", "version": "1.4.2", "signed_time": "...",
  "caller": { "repository": "...", "job_workflow_ref": "...", "ref": "...", "environment": "...", "run_id": "..." },
  "state": "running | converged | rolled_back | failed | paused",
  "phase": "queued | fetching | verifying | pushing | updating | waiting | handed_off | done",
  "steps": [ { "phase": "fetching", "started": "...", "ended": "...", "note": "image 812 MiB, sha256 ..." } ],
  "error": { "token": "bundle_signer", "detail": "..." },
  "started": "...", "ended": "..."
}
```

Error tokens in a record: `fetch_failed` (an HTTP error, a short body, a timeout, a full disk), `url_not_allowed` (a redirect to a host
not in `redirect_hosts`, to a non-`https` URL, to a non-public address, or more than 5 hops), `too_large`, `tar_invalid`,
`digest_mismatch` (the tar's manifest is not `image_digest`), `bundle_invalid` (not a parseable Sigstore bundle), `bundle_subject` (the
bundle does not attest the tar's SHA-256 under the service's `artifact_name`), `bundle_signer` (an identity check of section 3.3 step 2),
`bundle_chain` (the chain, the log entry or the timestamp does not verify against the trusted root), `older_than_running`,
`platform_mismatch`, `registry_failed`, `swarm_refused`, `swarm_rolled_back`, `swarm_paused`, `timeout`, `interrupted`.

### 2.3 Config

One TOML file, `--config <path>`, read at start (a change is a new Swarm config and a restart). Unknown keys are refused.

```toml
registry = "127.0.0.1:5000"        # pushed to by the updater and named in image references; the updater shares the
                                   # node's network namespace (host network), so both resolve to the same registry
trusted_root = "/etc/docker-swarm-updater/trusted_root.json"   # Sigstore trusted root, a reviewed file (section 3.3)
redirect_hosts = ["objects.githubusercontent.com", "release-assets.githubusercontent.com"]
keep_previous = 3                  # converged digests kept per service besides the running one and Swarm's previous spec
min_free_bytes = 10737418240       # a deploy is refused (fetch_failed) if the state directory's disk would go below this

[[service]]
name = "app"                       # the {service} of the API
swarm_service = "app_server"       # the Swarm service it updates
repository = "app"                 # the registry repository name
platform = "linux/amd64"           # the tar's manifest must be for this platform
artifact_url = { owner = "example-org", repo = "app" }   # URLs must be https://github.com/<owner>/<repo>/releases/download/<tag>/<file>
artifact_name = "app-*-linux-x86_64.image.tar"           # one `*`: the in-toto subject name and the URL's file name must match it
max_image_bytes = 4294967296       # optional; absent = no cap
signer = { repository = "example-org/app", repository_id = "123456789", workflow = ".github/workflows/artifacts.yml",
           ref = "refs/heads/main", triggers = ["push"] }
converge_timeout_secs = 0          # 0 = wait for Swarm however long the service's drain takes
  [[service.caller]]               # every listed claim must be equal; at least one caller per service
  repository = "example-org/app"
  repository_id = "123456789"
  job_workflow_ref = "example-org/docker-swarm-updater/.github/workflows/deploy.yml@<40 hex>"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
```

A service may list several `[[service.caller]]` entries; moving callers to a new pin of the reusable workflow is: add a caller entry
with the new `job_workflow_ref` (and the proxy's matching rule), move the callers, then remove the old entry.

The config check at start refuses: two services on one `swarm_service`; a caller with an empty claim; a `signer.workflow` that is not a
path under `.github/workflows/`; an `artifact_name` with no `*` or more than one; a `redirect_hosts` entry that is not a bare host name;
a `trusted_root` that is not a regular file owned by uid 0 or by the updater's own effective uid, or that is writable by group or
other (tests use the second owner, so they need no root).

### 2.4 Flags and verbs

`serve --config <file> --socket <path> --socket-group <gid> --proxy-uid <uid> --state-dir <dir> --docker <unix socket path>
[--allow-local-operator] [--ca-file <pem>]`. `--ca-file` replaces the built-in roots for downloads (tests and private mirrors). No
setting is read from the environment. Other verbs: `import`, `probe` (section 4).

## 3. Steps of one deploy

### 3.1 Before anything is fetched

In this order; each refusal writes no record:

1. the peer and header rules of section 1; the claims parse; `exp` is in the future (`expired`); the `jti` is new (`replayed`; it is
   recorded now);
2. `{service}` is configured and one of its callers equals the claims (the local operator skips this mapping); the body parses; `signer`, if present, matches; both URLs
   pass the URL rules of 3.2;
3. **idempotency per (service, digest)**: if a record for `image_digest` of this service is running, or the last record for it
   converged and Swarm runs it on every task, answer 200 with that record;
4. no deploy of another digest of this service runs (`busy`); no self-update runs (`self_update_busy`); for a self-update, no deploy
   of any service runs (`self_update_busy`); and `image_digest` is not in
   the service's failed list (`previously_failed`).

Then the record is written with state `running`, phase `queued`, and the answer is 202.

### 3.2 Fetch

- **The URLs** are parsed, never compared as strings: scheme `https`, host exactly `github.com`, no user info, port, query or fragment,
  path segments exactly `<owner>`, `<repo>`, `releases`, `download`, `<tag>`, `<file>` with `owner` and `repo` from `artifact_url`, no
  segment that is empty, `.`, `..` or contains `%` or `\`. `<file>` must match `artifact_name` (the bundle's is that name plus
  `.sigstore.json`).
- **Redirects**: at most 5, each to `https` on a host in `redirect_hosts`. Every host is resolved once and the connection goes to the
  checked address; a loopback, private, shared (100.64.0.0/10), link-local or unique-local address is refused. No token is sent.
- The tar streams to a file in the state directory while its SHA-256 is computed, with a 30 s connect timeout and a 60 s timeout on
  each read. It is refused `too_large` past `max_image_bytes`, and `fetch_failed` when the disk would go below `min_free_bytes`; a partial
  file is removed.

### 3.3 Verify, offline

1. **The bundle** parses as a Sigstore bundle (v0.1 to v0.3), else `bundle_invalid`. Its certificate chains to the trusted root's
   certificate authority, and at least one time source verifies against the trusted root: a transparency-log entry (public-good
   Sigstore bundles carry one) or an RFC 3161 timestamp (GitHub's own instance, for private repositories, carries one and no log entry)
   [E] (GitHub's artifact-attestation pages). The certificate is valid at that verified time, which becomes the record's `signed_time`.
   No network access: the trusted root is a file and the bundle carries every proof.
2. **The identity**, from the configured signer, on the certificate's extensions [E] (Fulcio's OID list, `1.3.6.1.4.1.57264.1.8` to
   `.24`): the subject alternative name equals `https://github.com/<repository>/<workflow>@<ref>`; the issuer equals the token issuer;
   the source repository identifier equals `repository_id` (a renamed or re-created repository is refused); the runner environment is
   `github-hosted`; the build trigger is in `triggers`; the run invocation URI is under `https://github.com/<repository>/actions/runs/`.
   Any difference is `bundle_signer`. The signer's repository must protect the signing branch; the updater cannot see that, and section 8
   says what follows if it does not.
3. **The subject.** The bundle's DSSE envelope signs an in-toto statement whose subjects include one entry with the tar's SHA-256 and a
   name matching `artifact_name`, else `bundle_subject`. The predicate type is SLSA provenance v1. So a validly signed tar of another
   artifact of the same release (another service's image, a binary) is refused.
4. **The digest.** The tar is an OCI image layout [E] (`image-layout.md` of the OCI image spec): `oci-layout`, `index.json`, `blobs/`.
   `index.json` has exactly one manifest whose digest equals `image_digest` (`digest_mismatch`); every blob the manifest and its config
   name is in the tar and hashes to its name (`tar_invalid`); the config's `os/architecture` equals `platform` (`platform_mismatch`).
5. **Not older than what runs.** `signed_time` must not be earlier than the `signed_time` of the service's last converged deploy
   (`older_than_running`). A valid caller can therefore not move a service back to an older release, even one the signer made; the local
   operator can, with `allow_older: true`, which the record names.

Step 4's comparison of the `index.json` manifest digest with `image_digest` runs first, before steps 1 to 3 (it reads one small
file). A failure adds `image_digest` to the failed list only when it is bound to that digest: a failure of steps 1 to 3, or of step 4's
blob and platform checks, after that comparison matched. A wrong URL or a tar of another digest does not block the right release, and
`older_than_running` never enters the failed list (the operator's `allow_older` retry must run). Nothing reaches the
registry or Swarm.

**The trusted root** is a file the operator keeps: produced by `gh attestation trusted-root` (it covers the public-good instance and
GitHub's own) [E] (GitHub's offline verification page), reviewed, installed by hash. When a key in it rotates, new bundles fail
`bundle_chain` until it is refreshed; List shows the root's newest key's validity so the date is visible before that happens.

### 3.4 Push

The tar's blobs and manifest are written to `<registry>/<repository>` through the distribution API [E]
(`distribution.github.io/distribution/spec/api/`): `HEAD` each blob, upload the missing ones, `PUT` the manifest by digest with its own
media type, then `HEAD /v2/<repository>/manifests/<image_digest>` must answer that digest (`registry_failed` otherwise). The bytes are
pushed as they are, so the registry's digest is the attested one by construction. No tag is pushed. A `docker load` is never used: the
daemon's classic image store re-creates manifests on push, so the digest would not survive [I].

### 3.5 Update and wait

1. Read the Swarm service (`GET /services/{id}`) and its running tasks; keep its `Version.Index`, its `UpdateStatus` and the time.
   If Swarm already runs the image (the spec names `<registry>/<repository>@<image_digest>`, every running task runs it, and the
   `UpdateStatus` is absent or terminal, so no update is moving tasks), no update is asked for: the deploy is `converged` (step 4)
   and its record says so. An update would change only the labels, and Swarm starts no rollout and writes no `UpdateStatus` for a
   spec whose task template is unchanged, so a wait for one would never end.
2. `POST /services/{id}/update?version=<index>` with **the spec just read, changed in exactly three places**: `TaskTemplate.ContainerSpec.Image
   = <registry>/<repository>@<image_digest>` and two service labels, `org.docker-swarm-updater.deploy` (the deploy id) and
   `org.docker-swarm-updater.digest`. A version conflict is retried once after a fresh read; a second is `swarm_refused`.
3. Poll every 2 s. An `UpdateStatus` counts only once it belongs to this update: `Version.Index` is past the one read in step 1 and
   `UpdateStatus.StartedAt` is later than step 1's time; a terminal state left by an earlier update is ignored. Without a status of this update,
   a Swarm that runs the new image as step 1 defines it is `converged` (an earlier update still moving tasks is waited for first). Then: `completed` with every running task on the new image and none on another is `converged`; `rollback_completed` is
   `rolled_back`; `paused` or `rollback_paused` is `paused` (a person must look); `converge_timeout_secs` passed (when non-zero) is
   `timeout`, and the update is left to Swarm. The task states and their errors go into the record's last step.
4. On `converged`: the service's signed-time floor becomes this `signed_time`; every manifest of the repository that is neither
   running, nor in Swarm's `PreviousSpec`, nor among the last `keep_previous` converged digests is deleted by digest. Blobs are freed by
   the registry's own garbage collection, which needs the registry read-only and is the operator's [E] (distribution's garbage-collection
   page).
5. On `rolled_back`: `image_digest` goes into the failed list.

### 3.6 State, concurrency, restarts, self-update

- **State** is files in `--state-dir`, each written to a temporary name and renamed: `deploys/<id>.json`, `services/<name>.json`
  (failed digests, converged digests, the signed-time floor), `jti/` (accepted ids until their `exp`; pruned at each start and hourly).
  No database. Swarm's service spec is the source of truth for what runs; the files say what was asked and what happened. The files
  survive a hand-made change of the spec, which labels alone would not.
- **One deploy per service at a time**, decided in memory under one lock and written in the record before the 202. Deploys of
  different services run at once.
- **A restart** reads every record in state `running`. In phases `queued` to `pushing`, nothing in Swarm changed: `failed`
  `interrupted`, and the caller may ask again. In `updating`, `waiting` or `handed_off`, it reads the service's `UpdateStatus` with the
  rule of 3.5 step 3 against the record's start: `rollback_completed` is `rolled_back`; `completed` with the record's digest running is
  `converged`, and so is a Swarm that runs the record's image with no update in flight and no status after the record's start;
  `updating` resumes the wait; a spec that no Swarm update of this record explains (another deploy label and no update
  status after the record's start) is `failed` `interrupted`.
- **Self-update.** At start the updater reads its own service from its task's labels. A deploy of that service runs 3.1 to 3.4, requires
  that no other deploy runs, writes phase `handed_off`, then asks Swarm for the update. Swarm stops this task (stop-first) and starts the
  new one, which finds the record at start and settles it by the restart rule above. If the new task fails its health check, Swarm rolls
  back; the old image's new task finds `rollback_completed` and reports `rolled_back`. While no task runs, the proxy answers 503 and
  callers retry Status with new tokens.

## 4. Other verbs

### 4.1 `import`

`docker-swarm-updater import --config <file> --service <name> --tar <file> --bundle <file> --digest sha256:<d>`: runs 3.3 and 3.4 on local
files and prints the image reference. For bootstrap (the first updater pushes itself) and for operators adopting a running service. It
never touches Swarm, and it runs where `registry` resolves as it does for the daemon (the node's network namespace).

### 4.2 `serve`

The API of section 2 with section 2.4's flags.

### 4.3 `probe`

`docker-swarm-updater probe http://127.0.0.1:<port>/<path> [--timeout 2s]` or `probe --unix <socket> /<path>`: exit 0 when the answer
is 2xx, 1 otherwise; nothing on stdout. Many images have no shell or HTTP client, so Docker's `HEALTHCHECK` cannot call a readiness
route. The static binary can be mounted read-only into such a service and named in its `healthcheck.test`
(`["CMD", "/usr/local/libexec/docker-swarm-updater", "probe", "http://127.0.0.1:8080/readyz"]`); it needs nothing from the image. It
refuses an `http://` URL whose host is not a loopback address, so a health check cannot reach out of its task. The updater's own health
check is `probe --unix <its socket> /v1/health`.

## 5. Implementation

- **Rust**, edition 2024, toolchain pinned in `rust-toolchain.toml`. One binary, static (`x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`), and one container image `FROM scratch` holding the binary and nothing else (CA roots built in with
  `webpki-roots`; `--ca-file` replaces them). Apache-2.0.
- **Crates**: `dsu-core` (pure: config and its checks, claim and peer rules, URL rules, the record state machine, OCI layout reading,
  retention, the UpdateStatus rule; no I/O, no clock, `BTreeMap` only), `dsu-verify` (section 5.1), `dsu-docker` (the Docker Engine API
  subset over a Unix socket), `dsu-registry` (the distribution API subset), `dsu-server` (the HTTP API, state files, the deploy runner),
  `docker-swarm-updater` (the binary; `main.rs` forwards to `dsu-server`), `dsu-deploy` (the client the reusable workflow runs,
  section 7), `xtask` (repository checks and the release steps of section 7).
- Each side effect is behind a narrow trait with a real implementation and the fake of section 6: `Docker`, `Registry`, `Fetch`
  (including name resolution), `Clock`, `PeerCred` (the credentials of a connection's peer; only the uid decides). Errors are `thiserror` enums with context in every
  library crate; `anyhow` only in the binary.
- `tokio` and `hyper` (server on a Unix socket, clients for the Docker socket and HTTPS with `rustls`). No `unsafe`; `SO_PEERCRED`
  through tokio's `UnixStream::peer_cred` (rustix's `UCred` holds the pid as a non-zero integer, so it cannot hold the kernel's pid 0).

### 5.1 The Sigstore verifier: the first item

Two candidates [E] (each crate's repository and documentation):

- `sigstore-verify` (the sigstore-rust workspace, Apache-2.0): verifies Sigstore bundles v0.1 to v0.3, GitHub's included, against a
  trusted root, never fetches, and takes an explicit identity and issuer policy.
- the `sigstore` crate (sigstore-rs): its README says attestation verification is not handled yet.

`dsu-verify` wraps `sigstore-verify` and adds the extension checks of 3.3 step 2 and the subject-name check of step 3. It is built
first, and must verify real GitHub attestation bundles of public releases offline from committed fixtures (a bundle, the trusted root
and the subject digest; the artifact itself is not needed). If it cannot verify a DSSE in-toto bundle offline, the fallback is a pinned
`gh attestation verify --bundle --custom-trusted-root` [E] (GitHub's offline verification page) inside the image, at the cost of the
single-binary image; that choice is made on that evidence, before any other code.

## 6. Tests

Everything runs in `cargo test` with no network, no Docker and no root: in-process fakes on loopback port 0 or on Unix sockets in a
per-test temporary directory; a fake clock; a fake `PeerCred`; one trusted root and signing chain made for the tests (a test CA standing
in for the certificate authority, a test log key and timestamp key), so good, tampered and wrongly signed bundles are made in the test,
not fetched. Real-world compatibility is the fixture test of 5.1. No test reads a duration from the real clock.

- **Fake Docker API**: services with `Spec`, `Version`, `UpdateStatus` (with `StartedAt`), `PreviousSpec` and tasks; a script per test
  says how an update goes (converges, rolls back, pauses, never ends, conflicts on version, refuses, is answered 200 and dropped, keeps a
  stale terminal state), an update that leaves the task template unchanged starts no rollout (as in Swarm), and it records every update
  body it received.
- **Fake release server**: HTTPS on loopback with the test CA (`--ca-file`); files, redirects (allowed host, other host, `http`, a loop,
  six hops), errors, a short body, a stalled read. The fake resolver maps the allowed host names to a documentation address
  (203.0.113.10) and others to private or loopback addresses; the fake connector dials 203.0.113.10 to the server's loopback port, so the
  code under test still refuses loopback and private answers.
- **Fake registry**: the distribution API subset by digest; modes that answer another digest or fail an upload.

| input | case | expected |
|---|---|---|
| happy path | good release, Swarm converges | `converged`; registry has the manifest by digest; the update body differs from the spec read in exactly `Image` and the two labels |
| idempotency | same (service, digest) after it converged; while it runs | 200 with that record, no fetch or update |
| concurrency | another digest of the service while one runs; two services at once | 409 `busy` with the running id; both converge |
| peer and claims | claims from `--proxy-uid`; claims from another uid; claims from uid 0; no claims from uid 0 with and without `--allow-local-operator`; no claims from another uid; no claims from `--proxy-uid`; `/v1/health` from another uid; no claims from uid 0 with pid 0 (outside the pid namespace) with and without `--allow-local-operator`; credentials unreadable, health and another route | accepted; 401 `bad_peer`; 401 `bad_peer`; accepted (record names the operator) / 401 `bad_peer`; 401 `bad_peer`; 401 `no_claims`; 200; accepted / 401 `bad_peer`; 200 / 401 `bad_peer`; each 401 and 403 logged with its reason |
| claims | malformed header; expired `exp` (401 `expired`); `jti` reused on Deploy, on Status, after a restart; a refused request's `jti` reused; `jti` files after `exp` (fake clock) | 400; 401; 401 `replayed` each; 401 `replayed`; pruned |
| mapping | caller of service A deploys B; reads a record of B; lists | 403 `not_allowed`; 404 `unknown_deploy`; only A's services |
| request | unknown service; unknown field; `allow_older` from a caller; `signer` differing in one field; body of 16 KiB + 1 | 404; 400; 400; 403 `signer_mismatch`; 413 |
| request target | `%2e%2e`, `..`, `//`, trailing `/`, upper case, a query string; `GET` on the deploy path | 404 each; 405 |
| URLs | another owner or repo; `..` or `%` in a segment; a port, user info, query; file name not matching `artifact_name` | 403 `url_not_allowed` each |
| fetch | 404; short body; stalled read (fake clock); redirect to an allowed host; to another host; to `http`; to a host resolving to 127.0.0.1 or to 100.64.0.1; a loop; six hops; over `max_image_bytes`; disk below `min_free_bytes`; a write failing midway | `fetch_failed`; `fetch_failed`; `fetch_failed`; `converged`; `url_not_allowed` (each of the next five); `too_large`; `fetch_failed`; `fetch_failed`, partial file gone |
| bundle | not JSON; tar changed after signing; signed by another workflow, ref, repository id, trigger, a self-hosted runner, a run of another repository; chain from another root; log entry altered; timestamp only (no log entry), valid; neither; a valid bundle of another artifact of the same release | `bundle_invalid`; `bundle_subject`; `bundle_signer` each; `bundle_chain`; `bundle_chain`; `converged`; `bundle_chain`; `bundle_subject` |
| tar | `index.json` digest differs; two manifests; a missing blob; a mis-hashed blob; another platform | `digest_mismatch`; `tar_invalid`; `tar_invalid`; `tar_invalid`; `platform_mismatch` |
| failed list | after `bundle_signer` with the right digest; after `digest_mismatch`; clear by the operator; clear through the proxy | retry 409 `previously_failed`; retry runs; 204 and the next deploy runs; 403 |
| downgrade | signed earlier than the running release, by a caller; by the operator with `allow_older` | `older_than_running`; `converged`, record says so |
| registry | upload fails; answers another digest | `registry_failed`; Swarm untouched |
| Swarm | rolls back; pauses; timeout set and never completes (fake clock); timeout 0 and completes late; version conflict once, twice; a stale `rollback_completed` from an earlier update before this one starts; already runs the image on every task; already names the image while an earlier update still moves a task, so the update starts no rollout; a restart after such an update, with no `UpdateStatus`; answers the update 200 and changes nothing | `rolled_back` and digest in the failed list; `paused`; `timeout`, no rollback call; `converged`; `converged`, `swarm_refused`; ignored, then `converged`; `converged` with no update asked for, the service free; `converged` once the earlier update settles; `converged` at start; `failed` `interrupted`, the service free |
| restart | in `fetching`; in `waiting` while Swarm still updates; after Swarm completed; after Swarm rolled back; with a spec changed by hand | `failed interrupted`; resumes to `converged`; `converged`; `rolled_back`; `failed interrupted` |
| self-update | converges; new image unhealthy and Swarm rolls back; asked while another deploy runs; another deploy asked while it runs | new task settles `converged`; old image's task settles `rolled_back`; 409 `self_update_busy`; 409 `self_update_busy` |
| local operator | Deploy with no claims as uid 0 | runs for any service; record's caller `operator (uid 0)` |
| retention | after a converge with five earlier digests | running, previous and the last three kept; the others deleted by digest |
| config | each refusal of 2.3; `--proxy-uid 0` | start refused naming the key or flag |
| health, probe | `/v1/health` with Docker answering and not; `probe`: 200, 503, refused, timeout, non-loopback URL, `--unix` | 200, 503; 0, 1, 1, 1, refused, 0 |
| deploy client (`dsu-deploy`) | Deploy 202 then Status to `converged`; Deploy answered `converged`; ending `failed`, `rolled_back`, `paused`, an unknown state; Deploy or Status refused; a 503 or a connection failure on Deploy, on Status; never accepted, never final within `wait-minutes` (fake clock); `wait-minutes` 0; GitHub mints no token; an answer that is not the deploy's record; a `version` of 128 and 129 bytes; no token-request bearer | exit 0, a new token per request; exit 0, no Status; exit 1 with the record's error each; exit 1 with the answer's error; retried each; exit 1 "not accepted", "still running; it continues"; waits on; exit 1, nothing sent; exit 1; accepted, exit 2; exit 2 |
| release (`cargo xtask release`) | a program printing exactly the expected line, another line, a prefix, or exiting non-zero; the image written twice, with another time; the image verified by the updater for its platform, for the other; a binary with and without a program interpreter, a truncated or 32-bit ELF; a release directory exact, with a file missing or extra; a stamped workspace | passes, fails, fails, fails; the same bytes, other bytes; verifies, `platform_mismatch`; refused, passes, refused; `SHA256SUMS` written, refused; only workspace crates move in `Cargo.lock` |
| the workflows | `deploy.yml` called with the required inputs only, with every optional one, on a runner without `job.workflow_*`; the Deploy outcome `converged` and `rolled_back`; `artifacts.yml` and every workflow as committed, and copies each with one boundary broken (a write or signing permission on another job, another trigger, a top-level grant, repository code in `attest`, `publish` before `verify`, `attest` off `main`, an action pinned by tag) | the client gets every input as its flag with the defaults, the checkout is the workflow's own commit; the job passes, fails; stops before the checkout; the check passes; it names that boundary |

Why this list is complete: every input the program takes is one row group (peer, claims, mapping, request, request target, URLs,
release server, bundle, tar, registry, Swarm, its own restart, config), and each group has its good case, every refusal the code names in
sections 1 to 3 for that input, and the boundary between them (once and twice for retries, zero and non-zero for timeouts, before and
after the hand-off for restarts, the size and free-space limits). A new error token or refusal in sections 1 to 3 needs a row here.

## 7. Repository conventions

- `rust-toolchain.toml` pins the stable toolchain. The `lint` check runs `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --locked -- -D warnings` and `cargo deny check bans licenses sources` with a pinned, checksummed `cargo-deny`; advisories
  run in their own workflow and never block a PR. Permissive licences only; crates.io only.
- The `test` check runs `cargo llvm-cov` with branch coverage under nextest; every crate needs at least 99% of lines and of branches;
  no coverage exclusions.
- Workflows: GitHub-hosted runners only, actions pinned by commit, top-level `permissions: {}`, each job granting only what it uses,
  actionlint clean.
- Releases from `main`: each push to `main` runs `artifacts.yml` (a newer push waiting for the previous run supersedes an older
  one that has not started), which releases `v<major>.<minor>.<commits on main>` (the same commit
  always gets the same version, a later one a higher one) with, for `linux-x86_64` and `linux-arm64`, the static binary and the image
  tar: an OCI layout written by `cargo xtask release image`, `FROM scratch`, the binary at `/docker-swarm-updater` as the entrypoint,
  user `65532:65532`, every time the commit's, plus Docker's `manifest.json` so `docker load` reads it. Before signing it checks that
  the binary has no program interpreter and prints the version, that rebuilding the workspace's crates gives the same binary byte for
  byte, that the image written twice is the same bytes, and that the image loads and runs. Only its `attest` job holds
  `id-token: write` and `attestations: write`, and runs no repository code; each binary and image gets its own `.sigstore.json`, which
  `verify` checks against this signer before `publish` creates the release. `artifacts.yml` is the signer identity, so it is never
  renamed.
- **The reusable workflow** `.github/workflows/deploy.yml` (`on: workflow_call`). Inputs: `service`, `version`, `image-digest`,
  `image-url`, `bundle-url`, `signer-repository`, `signer-workflow`, `signer-ref` (the last three default to the caller's repository,
  `.github/workflows/artifacts.yml` and `refs/heads/main`), `endpoint`, `audience`, `environment`, `wait-minutes` (default 60),
  `tailscale-oauth-client-id`, `tailscale-audience`, `tailscale-tags` (optional; Tailscale's workload identity needs the client id and
  its audience). Its one
  job declares `permissions: { id-token: write }` and `environment: ${{ inputs.environment }}` (a job that calls a reusable workflow
  cannot name an environment itself [E], GitHub's reusable-workflow reference), so the environment and its protection rules belong to
  the calling repository and the token's `environment` claim exists only once that job may run. The environment needs no required
  reviewer: a release deploys when its workflow runs, and what protects the path is the environment's deployment branches (the
  signing branch only), the claims the proxy and the updater check (repository, repository id, `job_workflow_ref`, ref, environment,
  runner), the attestation check, the signed-time floor and Swarm's rollback. The caller's job grants `id-token: write`. Steps: an
  optional network step (when `tailscale-oauth-client-id` is set, the job joins that Tailscale network as an ephemeral node with
  `tailscale/github-action`, pinned by commit, Tailscale itself pinned by version and SHA-256, before any call; when empty, the step is
  skipped); then the client `dsu-deploy`, built from the workflow's own commit (the `job` context's `workflow_repository` and
  `workflow_sha`), which asks for a new OIDC token with `audience` for every request, sends Deploy, then Status every 10 s until a
  final state or `wait-minutes` (0: no limit), retrying a 503 or a connection failure on either. `converged` passes; any other final
  state fails the job with the record's error; `wait-minutes` passing fails it with "deploy <id> still running; it continues". One
  deploy per service at a time runs from a calling repository (a `concurrency` group per service).
- The caller's workflow must run on its signing branch (a `push` to it or a `workflow_run` of its release workflow there), not on a
  `release` event, because the token's `ref` claim is the triggering ref.

## 8. What an attacker gains if this is wrong

| part | if it is wrong | what still holds |
|---|---|---|
| the proxy passes unverified requests | a local process in the proxy's uid can call Deploy for any caller's claims | the configured signer, the subject name and the signed-time floor: only a newer release the configured workflow signed for that service can be deployed |
| the proxy itself is taken over | it can present any claims | the same three checks; nothing else |
| the claim mapping is too wide | a listed caller deploys a service it should not | the service's configured signer and `artifact_name`: only that service's own signed images |
| the signer's branch is unprotected, or its workflow is changed by a writer | a writer of the signer repository can sign an image | nothing in the updater; the signer repository's branch protection and review are the control; Swarm rolls back an image that fails its health check |
| the caller's environment is opened to other branches by an admin of the calling repository | a workflow run on another branch gets the `environment` claim | the `ref` claim, matched exactly by the proxy and the updater, and the signer checks; the updater cannot see environment settings |
| the verifier accepts a bad bundle | an attacker's image runs as the service, with its secrets and mounts | the URL rules (the asset must be in the signer's own releases) only; the digest is the caller's, so it is not an independent check |
| the Docker socket | the updater holds the Docker API, which is root on the node and everything the node holds (every service's secrets, every service it runs) | no TCP listener; a `FROM scratch` image, read-only, all capabilities dropped; the only update body it sends is the read spec with three fields changed (a test asserts it); a socket-filtering proxy is an open question (section 9) |
| a token is captured | one request until `exp` | `jti` single use; the floor refuses older releases |
| the docker-swarm-updater release pipeline itself | its next release deploys itself through its own caller | its own signer, claims and environment, as for any other service |
| the reusable workflow's commit | a caller pinned to it runs that commit's client | callers pin a full commit, and the proxy and the updater match `job_workflow_ref` exactly, so a change reaches no caller until its pin moves |

## 9. Open questions

- Whether `sigstore-verify` verifies DSSE bundles offline as its documentation says; section 5.1, the first thing built, answers it.
- Whether to put a socket-filtering proxy (only `GET` of services, tasks, nodes and version, and `POST /services/{id}/update`) between the
  updater and the Docker socket. It narrows a compromised updater from "root on the node" to "any spec on a managed service", which is
  still root-equivalent through mounts; recommended only if the update body can also be checked there.
- More than one manager running the updater: not needed until someone asks.

## 10. Decisions taken here

- Claims arrive in one header set by the proxy (`x-dsu-claims`, the base64url JSON payload), so the updater reads the same fields the
  proxy checked, and it checks the proxy's uid on every connection.
- Images are pushed blob by blob instead of `docker load` and `docker push`, so the registry digest is the attested one on any image store.
- State is files, not Swarm labels alone: records, the failed list and the floor must survive a hand-made change of a service's spec.
- No deploy is rolled back by the updater; Swarm's `failure_action` does it, and the updater reports it.
- A release older (by verified signing time) than the running one is refused unless the local operator asks; rolling back is an
  operator's act, not a caller's.
- Verification failures are records (202, then `failed`), because they are found after the download; refusals found from the request
  alone are 4xx and write no record.
