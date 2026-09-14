# Bijuus Roo — checklist de publicação

## Código
- [x] Frontend servido pelo backend
- [x] PostgreSQL
- [x] Sessões HTTP-only
- [x] Senhas com scrypt
- [x] Aprovação/bloqueio/reativação
- [x] Snapshots e IFP no servidor
- [x] PvP no servidor
- [x] Auditoria
- [x] Recuperação de senha
- [x] Caddy/HTTPS via Compose
- [x] Backup e restore

## Infraestrutura ainda necessária
- [ ] Servidor VPS/Cloud real provisionado
- [ ] DNS do domínio apontado para o servidor
- [ ] `.env` de produção criado com segredos reais
- [ ] Primeiro deploy executado
- [ ] HTTPS confirmado no domínio
- [ ] Login admin testado em produção
- [ ] Cadastro + aprovação testados com 2 contas
- [ ] Snapshot/status testado em produção
- [ ] Backup criado e restaurado em ambiente de teste
- [ ] PvP testado em banco real
- [ ] Logs/monitoramento verificados
- [ ] Política de backup/retencao definida
- [ ] Senha inicial do admin trocada

## Critério
Só marcar `PRONTO PARA PUBLICAR` quando todos os itens de infraestrutura e teste acima estiverem concluídos.
