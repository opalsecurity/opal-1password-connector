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

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
	&& useradd --uid 10001 --create-home connector \
	&& mkdir -p /data /opt/op && chown connector:connector /data
COPY --from=build /opal-1password-connector /usr/local/bin/opal-1password-connector
USER 10001
# Device trust lives here; losing it triggers a new-device sign-in (and 2FA if enforced).
ENV OP_CONFIG_DIR=/data/op GIN_MODE=release
# The 1Password CLI is not bundled: deployments mount it at /opt/op from 1Password's official
# 1password/op image (the Helm chart and Compose file do this; see README).
ENV PATH=/opt/op:$PATH
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["opal-1password-connector"]
