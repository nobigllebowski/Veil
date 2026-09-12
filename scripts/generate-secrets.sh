#!/usr/bin/env bash
# Generates every secret the deployment needs and prints them in .env format.
# Usage: scripts/generate-secrets.sh > .env
set -euo pipefail

b64() { openssl rand -base64 32; }
pem() { openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt | awk 'BEGIN{ORS="\\n"} {print}' ; }

cat <<ENV
POSTGRES_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)
VEIL_FIELD_ENCRYPTION_KEY=$(b64)
VEIL_BLIND_INDEX_KEY=$(b64)
VEIL_IP_HASH_SALT=$(openssl rand -hex 16)
VEIL_JWT_SIGNING_KEY_PEM="$(pem)"
VEIL_DOMAIN=localhost
VEIL_OPENAPI_ENABLED=false
OTEL_EXPORTER_OTLP_ENDPOINT=
ENV
