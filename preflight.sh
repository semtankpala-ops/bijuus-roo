#!/usr/bin/env bash
set -euo pipefail
command -v node >/dev/null || { echo 'Node.js não encontrado'; exit 1; }
node --check server.js
node --check seed-admin.js
npm test
node -e "const p=require('./package.json'); if(p.type!=='module') process.exit(1); console.log('package.json OK')"
for f in schema.sql migrations/002_v27.sql Dockerfile docker-compose.yml docker-compose.prod.yml docker-entrypoint.sh backup.sh Caddyfile; do test -s "$f" || { echo "Arquivo ausente/vazio: $f"; exit 1; }; done
if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.prod.yml config >/tmp/bijuus_compose_check.txt
  echo 'docker-compose.prod.yml OK'
fi
printf 'PRE-FLIGHT V27 OK\n'
