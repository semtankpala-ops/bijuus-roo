# Bijuus Roo V28 — Release Candidate

Esta é a base de produção do sistema privado da guild Bijuus Roo.

A versão inclui autenticação de servidor, PostgreSQL, snapshots de status, IFP, medalhas, ranking, PvP, auditoria, recuperação de senha, backup/restore e HTTPS via Caddy.

## Preparação rápida
1. Instale Docker + Docker Compose no servidor.
2. Entre na pasta do projeto.
3. Execute `./setup-production.sh`.
4. Revise o `.env` gerado.
5. Execute `docker compose -f docker-compose.prod.yml up -d --build`.
6. Verifique `https://SEU-DOMINIO/api/health`.
7. Faça os testes do `RELEASE_CHECKLIST.md`.

## Importante
Este pacote não publica sozinho em um servidor externo. É necessário possuir um servidor e um domínio, ou um provedor de hospedagem que aceite Docker.
