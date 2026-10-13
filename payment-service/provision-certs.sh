#!/bin/sh
# Keep the authority and other services' private keys outside runtime mounts.
set -eu
/app/payment-server certs --dir /authority
copy() {
    destination=$1
    shift
    mkdir -p "$destination"
    for filename in "$@"; do cp "/authority/$filename" "$destination/$filename"; done
    chown -R 1001:1001 "$destination"
}
copy /payment ca.crt payment-service.crt payment-service.key payment-service-client.crt payment-service-client.key probe.crt probe.key
copy /account ca.crt account-server.crt account-server.key account-service.crt account-service.key probe.crt probe.key
copy /gateway ca.crt gateway.crt gateway.key
