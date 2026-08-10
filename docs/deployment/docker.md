# Docker Deployment Image

Splendor publishes a Docker deployment image for the 0.05-dev local runtime
smoke-test surface. The image is intended for installing and smoke-testing
Splendor on machines that do not have the Rust, Python, or TypeScript toolchains
installed.

## Scope

- Milestone: Splendor0.05-dev release packaging.
- Primitives represented: local runtime, governance, physical/edge development
  contracts, replay/audit, docs/tests, SDK/API packaging, local runtime
  deployment.
- Boundary: Docker image for the local governed runtime, `splendorctl`, the
  local runtime daemon binary, examples, and the Python SDK.
- Physical/edge boundary: the image can smoke-test 0.05 reference contracts and
  simulation examples; it is not production remote daemon packaging or physical
  hardware deployment.

## Non-goals

- No remote daemon exposure.
- No fleet registry, remote transport, or distributed scheduling.
- No production OAuth/OIDC, PKI, or mTLS rollout.
- No production physical hardware deployment, live robotics integration, or
  safety certification.
- No hard real-time robot control, motor control, raw actuator writes, firmware
  safety bypass, or direct cloud-to-actuator authority.
- No 0.1 stable compatibility guarantee.

## Pull the image

After the GitHub Container Registry package is public, install the released image
with Docker. Published release images support `linux/amd64` and `linux/arm64`:

```bash
docker pull ghcr.io/splendor-kernel/kernel:0.05-dev
```

Branch images are also published for integration smoke tests:

```bash
docker pull ghcr.io/splendor-kernel/kernel:dev
docker pull ghcr.io/splendor-kernel/kernel:main
```

## Verify the installation

```bash
docker run --rm ghcr.io/splendor-kernel/kernel:0.05-dev
```

Expected shape:

```text
splendorctl 0.1.0 (Splendor0.05-dev)
```

The default command is `splendorctl --version`. You can pass any `splendorctl`
command after the image name:

```bash
docker run --rm ghcr.io/splendor-kernel/kernel:0.05-dev \
  splendorctl run --config ./examples/local-basic-loop/config.yaml --cycles 1
```

To keep trace and state output on the host, mount a working directory and run
against your own config:

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/splendor-kernel/kernel:0.05-dev \
  splendorctl run --config ./splendor-run.yaml --cycles 1
```

## Local daemon security note

The image includes the `splendor-daemon` binary for local daemon and governance
development smoke tests. The current daemon binary intentionally binds to
`127.0.0.1:8077` inside the container and warns that it is running in explicit
local-only insecure development mode.

Do not publish an unauthenticated daemon TCP listener from this image as a remote
service. Production or fleet daemon communication requires authenticated caller
identity, endpoint scopes, signed work orders, expiry, revocation, and trace/audit
attribution before remote exposure.

## Build locally

```bash
docker build -t splendor:0.05-dev .
docker run --rm splendor:0.05-dev
```

The repository smoke test builds the image and verifies the CLI, Python SDK import,
local tick execution, trace export, state-head lookup, and inspect-only replay:

```bash
bash scripts/container-tests.sh
```

## Release tags

The Docker publish workflow emits:

- `ghcr.io/splendor-kernel/kernel:dev` from the `dev` branch;
- `ghcr.io/splendor-kernel/kernel:main` from the `main` branch;
- `ghcr.io/splendor-kernel/kernel:0.05-dev` and the Git tag name when a `v0.05*`
  release tag is pushed;
- `sha-<commit>` for immutable commit-addressed pulls.

Use an immutable `sha-<commit>` tag for reproducible automation and the milestone
tag for human release smoke tests.

Release administrators can also rerun the Docker Image workflow manually with
the release-publish input maintained by the package-label branch to republish the
`0.05-dev` and `v0.05-dev` image tags from the selected ref without moving the
Git release tag.

Release image manifests are published for both `linux/amd64` and `linux/arm64` so
Docker can select the native image on supported Intel/AMD and Apple Silicon/Linux
ARM64 machines.

Every branch, tag, and manual publication builds each platform candidate once,
without registry authority, and uploads the resulting Docker archive plus its
checksum. The `release-closure` job downloads that exact archive, verifies its
checksum and OCI `org.opencontainers.image.revision` label against the same
`GITHUB_SHA`, extracts its `splendorctl`, `splendor-daemon`, and
`splendor-manager` binaries, and rejects development Secret Provider/test-support
markers before smoke testing the same loaded image. It then publishes a checksum
receipt for that archive. Only later publication jobs receive `packages: write`;
they recheck the archive against the release-closure receipt and push the loaded
candidate without rebuilding it. Platform digest and manifest publication cannot
run when exact-artifact validation fails. Candidate, receipt, and digest artifact
names are scoped to the workflow run attempt so a partial rerun cannot mix prior
attempt bytes into a manifest; the manifest job also requires exactly two valid
platform digest filenames before registry login. Rerun all publication jobs to
produce a new attempt. The executable workflow guard rejects conditional or
failure-ignored release verification and any changed or additional one-time image
build input/build argument.

## GHCR package visibility

The publish workflow builds and pushes with GitHub's default `GITHUB_TOKEN`, but
package visibility changes require package-admin authority that the default token
does not have. For first-time public installs, a release administrator must either:

- set `ghcr.io/splendor-kernel/kernel` to public in GitHub's package settings; or
- configure a `GHCR_VISIBILITY_TOKEN` repository/organization secret from a
  package admin with package read/write authority so the workflow can make the
  package public after publishing.

If that secret is not configured, the publish workflow records a notice and stays
green after the image is pushed. Unauthenticated `docker pull` commands remain
blocked until the GHCR package visibility is made public.
