# syntax=docker/dockerfile:1

###############################################################################
# Build stage: two static binaries. CGO is disabled so the artifacts run
# unmodified on Alpine without glibc.
#
#   telemetry  the ingest + read API and the audit dashboard
#   shipper    the central audit logging consumer (follows container stdout)
#
# They share one image because they share one codebase and one config contract;
# the compose file runs the shipper from this same image with a different
# entrypoint (see docker-compose.yml).
###############################################################################
FROM golang:1.24-alpine AS build

WORKDIR /src

# Cache the module download layer (only invalidated when go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/telemetry ./cmd/telemetry \
 && CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/shipper ./cmd/shipper

###############################################################################
# Runtime stage: minimal Alpine, CA certificates, and a non-root user.
###############################################################################
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S telemetry \
    && adduser -S -G telemetry telemetry

WORKDIR /app

COPY --from=build /out/telemetry /app/telemetry
COPY --from=build /out/shipper /app/shipper
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod 0755 /app/entrypoint.sh

# The audit schema migrations are compiled into the binary (go:embed), so the
# runtime stage needs no SQL files and no external migration tooling.

# Non-root by default. The shipper service additionally joins the host's docker
# group (see docker-compose.yml) so it can read the Docker API socket without
# running as root.
USER telemetry

EXPOSE 8088

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:8088/readyz || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
