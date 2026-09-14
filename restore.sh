#!/usr/bin/env bash
set -euo pipefail
FILE="${1:-}"
if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "Uso: ./restore.sh backups/arquivo.dump"
  exit 1
fi

echo "ATENÇÃO: isso substitui os dados atuais do banco."
read -rp "Digite RESTAURAR para confirmar: " OK
[[ "$OK" == "RESTAURAR" ]] || { echo "Cancelado."; exit 1; }

docker compose -f docker-compose.prod.yml exec -T db psql -U "${POSTGRES_USER:-bijuus}" -d postgres -c "DROP DATABASE IF EXISTS \"${POSTGRES_DB:-bijuus_roo}\";"
docker compose -f docker-compose.prod.yml exec -T db psql -U "${POSTGRES_USER:-bijuus}" -d postgres -c "CREATE DATABASE \"${POSTGRES_DB:-bijuus_roo}\";"
cat "$FILE" | docker compose -f docker-compose.prod.yml exec -T db pg_restore -U "${POSTGRES_USER:-bijuus}" -d "${POSTGRES_DB:-bijuus_roo}" --clean --if-exists

echo "Restauração concluída."
