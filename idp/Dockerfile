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
    -o /out/idp-server ./cmd/server

###############################################################################
# Runtime stage: minimal Alpine with CA certificates (Supabase TLS) and a
# non-root user. The entrypoint runs migrations -> seed -> serve.
###############################################################################
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && addgroup -S idp \
    && adduser -S -G idp idp

WORKDIR /app

COPY --from=build /out/idp-server /app/idp-server
COPY entrypoint.sh /app/entrypoint.sh
# Keep the script executable after the non-root USER switch (classic-builder
# compatible; --chmod would require BuildKit).
RUN chmod 0755 /app/entrypoint.sh

# The migrations and seed scripts are compiled into the binary (go:embed),
# so the runtime stage needs no SQL files and no external tooling.

USER idp

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
