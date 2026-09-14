#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=".env"
if [[ -f "$ENV_FILE" ]]; then
  echo ".env já existe. Não vou sobrescrever."
  exit 0
fi
command -v openssl >/dev/null 2>&1 || { echo "Erro: openssl é necessário."; exit 1; }

DB_PASS="$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)"
SESSION_SECRET="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 48)"
ADMIN_PASS="$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 20)"

read -rp "Domínio do Bijuus Roo (ex.: bijuusroo.com.br): " DOMAIN
read -rp "E-mail do administrador: " ADMIN_EMAIL

cat > "$ENV_FILE" <<EOT
NODE_ENV=production
PORT=3000
POSTGRES_DB=bijuus_roo
POSTGRES_USER=bijuus
POSTGRES_PASSWORD=${DB_PASS}
DATABASE_URL=postgresql://bijuus:${DB_PASS}@db:5432/bijuus_roo
SESSION_SECRET=${SESSION_SECRET}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASS}
DOMAIN=${DOMAIN}
TRUST_PROXY=1
DB_SSL=false
EOT
chmod 600 "$ENV_FILE"

echo
echo "Produção preparada."
echo "Admin inicial: $ADMIN_EMAIL"
echo "Senha inicial do admin: $ADMIN_PASS"
echo "Guarde essa senha em local seguro e troque-a após o primeiro login."
echo
echo "Próximo passo: docker compose -f docker-compose.prod.yml up -d --build"
