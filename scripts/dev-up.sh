#!/usr/bin/env bash
# Starts only the backing services for local development (the API runs from your IDE / `dotnet run`).
set -euo pipefail
docker compose -f "$(dirname "$0")/../docker-compose.dev.yml" up -d
echo "PostgreSQL on localhost:5432 (veil/veil_dev_password), Redis on localhost:6379"
