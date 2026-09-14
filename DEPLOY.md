# Bijuus Roo — implantação

## O que o assistente já prepara
- gera senha forte do PostgreSQL;
- gera segredo forte de sessão;
- gera senha inicial aleatória do admin;
- cria `.env` com permissão 600;
- sobe app + PostgreSQL + Caddy;
- Caddy termina HTTPS no domínio informado.

## O que precisa existir fora do projeto
- servidor com Docker;
- domínio DNS apontando para o IP do servidor;
- portas TCP 80 e 443 liberadas;
- armazenamento persistente e política de backup.

## Comandos
`./setup-production.sh`
`docker compose -f docker-compose.prod.yml up -d --build`
`curl -f https://SEU-DOMINIO/api/health`
`./backup.sh`
`./restore.sh backups/arquivo.dump`
