# Cross-compiles on the build host for each target platform.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-X github.com/opalsecurity/opal-1password-connector/onepasswordconnector.Version=${VERSION}" \
    -o /opal-1password-connector .

# The 1Password CLI is pinned by version and checksum (stderr classification depends on its wording).
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS op
ARG TARGETARCH
ARG OP_VERSION=2.34.0
ARG OP_SHA256_amd64=198b05dcf9a0972778ce5a4e262c459979b0c837257b5da65e2fba6187734226
ARG OP_SHA256_arm64=7b5c361a23e738a3969cf676960f4843af4aa9aa68dbec23d18a9134da428ba3
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
	&& curl -fsSLo /tmp/op.zip "https://cache.agilebits.com/dist/1P/op2/pkg/v${OP_VERSION}/op_linux_${TARGETARCH}_v${OP_VERSION}.zip" \
	&& eval "echo \"\${OP_SHA256_${TARGETARCH}}  /tmp/op.zip\"" | sha256sum -c - \
	&& unzip /tmp/op.zip op -d /usr/local/bin

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10001 --create-home connector \
	&& mkdir -p /data && chown connector:connector /data
COPY --from=op /usr/local/bin/op /usr/local/bin/op
COPY --from=build /opal-1password-connector /usr/local/bin/opal-1password-connector
USER 10001
# Device trust lives here; losing it triggers a new-device sign-in (and 2FA if enforced).
ENV OP_CONFIG_DIR=/data/op GIN_MODE=release
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["opal-1password-connector"]
