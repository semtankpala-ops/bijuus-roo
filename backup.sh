#!/usr/bin/env bash
set -euo pipefail
mkdir -p backups
STAMP=$(date +%Y%m%d_%H%M%S)
docker compose -f docker-compose.prod.yml exec -T db pg_dump -U "${POSTGRES_USER:-bijuus}" -d "${POSTGRES_DB:-bijuus_roo}" -Fc > "backups/bijuus_roo_${STAMP}.dump"
echo "Backup criado em backups/bijuus_roo_${STAMP}.dump"
