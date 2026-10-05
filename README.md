# SDLC image provenance action

Add one step to send image metadata, with a Sigstore attestation when available, to every authorized
SDLC region. No stack IDs, regional URLs, or Grafana secrets are required in CI.
The action exchanges GitHub OIDC with the global GitHub App, discovers destinations,
and sends each region its own short-lived gateway-signed ingestion token. The
regional ingester verifies that token locally and fans out to its authorized stacks.
Provenance signature verification remains the image processor's responsibility.

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  # Preserve any permissions your existing publishing workflow needs.
steps:
  # Existing checkout, registry login, build setup and image build/push...
  - uses: YOUR_ORG/YOUR_ACTION_REPO@YOUR_REF
    with:
      image: ghcr.io/acme/app
      digest: ${{ steps.build.outputs.digest }}
```

Replace the action reference with this repository's published location and pin a
reviewed commit. The composite action uses pinned Node 24 actions; use a runner version supporting
Node 24. No shell-installed runtime or package installation is required.
If native attestation generation fails (for example, the repository's GitHub plan
cannot persist private attestations), the action warns and sends the image metadata
without an attestation. GitHub OIDC authorization remains required. The output
`attestation-status` is `sigstore` or `unavailable`; the processor stores the latter
with `attestation_verified=false`. This is a build's authenticated report of an
image digest, not cryptographic proof that the image was built from that source.
A supplied bundle that cannot be read or validated still fails; it never falls back.
The default generates SLSA provenance with `actions/attest@v4` and never pushes
attestations to a registry. To keep an existing attestation step, pass its
`bundle-path` output to this action; native generation is then skipped. Upload-only
mode still requires `id-token: write` for the gateway exchange.

The optional `gateway-url` is an HTTPS origin, defaulting to
`https://sdlc-github.grafana.net`. This is the intended deployment hostname; this
repository does not provision its DNS or service. For development/custom deployments,
set the override to the deployed App origin. GitHub OIDC audience is that origin.
The action calls `/v1/ingest/auths` and receives
`{"destinations":[{"url":"https://eu.example/github/v1/logs","token":"..."}]}`.
Regional URLs are validated as HTTPS OTLP endpoints. Redirects are rejected on
both the exchange and delivery calls. Both credential types are masked and kept
out of event payloads.

Each region retries independently, up to three attempts. A failed delivery refreshes
its authorization before retrying, without resending successful regions. Revoked
destinations fail closed. The action fails if any originally discovered destination
fails; a workflow rerun may duplicate earlier deliveries, so consumers deduplicate
by `(stack_id, event_id)`. Newly added regions are picked up on the next invocation.

Use a fully qualified image name without tag or digest and its SHA-256 manifest
or index digest. An unpublished image can be attested if that digest is known.
A local Docker image ID or a hash of an exported tarball is not interchangeable
with the digest later observed by Kubernetes. Multi-platform index and platform
manifest digests can also differ; this prototype does not resolve those mappings.

## Event contract

`POST /github/v1/logs`, `Content-Type: application/json`, OTLP ExportLogsServiceRequest.
The receiver routes by event name; no topic URL or custom topic header is needed.
One log record named `grafana.sdlc.image.provenance` has the string attribute
`grafana.sdlc.event.id` and a JSON-string body:

- `schema_version`: 2.
- `image`: `name` and `digest`.
- `attestation`: `sigstore` or `unavailable`.
- `provenance`: the complete Sigstore bundle, required for `sigstore` and omitted for `unavailable`.

The ingester publishes each OTLP record to Kafka topic `images`, keyed by event ID.
The uploader structurally checks the subject and provenance type, but does not
verify signatures. It retries network errors and transient HTTP failures up to
three times using the same event ID and payload. Delivery is at least once;
consumers must deduplicate if needed. Changing the image reference or bundle produces a different ID. Unattested IDs also include repository ID, run ID, and attempt. Oversized bundles fail locally rather than being truncated.

### Team ownership

The global GitHub App resolves repository-default teams from CODEOWNERS at the
repository and SHA in the authenticated GitHub OIDC identity. It signs the handles
in the regional ingestion token. The ingester attaches them as trusted resource
metadata after removing caller-supplied GitHub attributes. An absent claim means
unknown ownership; an empty array means known unassigned.

The Action performs no team lookup or diff computation, and sends no unsigned
source metadata or publication assertion. The image processor obtains source
identity from the authenticated run, and additionally verifies the matching signed provenance when a bundle is present.

Run unit and HTTP transport tests with `node --test` (no package installation).

The global App verifies the signed repository and owner IDs against saved grants
and live installation access, and validates stack ownership before issuing tokens.
Knowing a stack ID grants no access. Any OIDC-capable job in an activated repository
is eligible; the MVP does not restrict branches or authenticate the composite action
itself. Tokens expire after five minutes, bounding the delay for revocation.
