# syntax=docker/dockerfile:1

###############################################################################
# Build stage: compile a static binary. CGO is disabled so the artifact runs
# unmodified on Alpine without glibc.
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
    -o /out/payment-server ./cmd/server

###############################################################################
# Runtime stage: minimal Alpine with CA certificates and a non-root user.
#
# The ledger migrations are compiled into the binary (go:embed), so the runtime
# stage needs no SQL files and no external migration tooling.
#
# The certificate material is NOT baked in. The development CA and its
# certificates are generated at startup into ./certs on the host and mounted
# read-only (see docker-compose.yml), because a private key in an image layer is
# a private key handed to everyone who can pull the image.
###############################################################################
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S payment \
    && adduser -S -G payment payment

WORKDIR /app

COPY --from=build /out/payment-server /app/payment-server
COPY entrypoint.sh /app/entrypoint.sh
COPY provision-certs.sh /app/provision-certs.sh
RUN chmod 0755 /app/entrypoint.sh

USER payment

EXPOSE 8081

# The health check is declared in docker-compose.yml, not here: it has to present
# a client certificate and read the paths the environment names, and a probe that
# silently disagrees with the running configuration is worse than no probe.

ENTRYPOINT ["/app/entrypoint.sh"]
