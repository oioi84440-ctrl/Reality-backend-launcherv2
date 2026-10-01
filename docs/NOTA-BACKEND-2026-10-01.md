# NOTA DE ESTADO — backend Reality Client (2026-10-01)

Round de seguranca aplicado no backend (F01, F02, F05, F06, F07, F09, F16, F17).
O codigo esta RODANDO em producao; o que falta esta listado abaixo.

## O que esta no ar

* `https://16-5-7-132.sslip.io` (TLS Let's Encrypt, HSTS) + `http://` redirecionando
  (301). `http://16.5.7.132:3000` segue em HTTP puro para nao quebrar o launcher atual.
* Assinatura Ed25519 do feed de update (`sig` em `/api/update`, header
  `x-reality-manifest-sig`, `GET /api/manifest.sig`, chave publica em `GET /api/pubkey`).
* Rate limit do `/api/redeem` por IP real + por conta + GLOBAL, com
  `data/redeem-abuse.json`.
* Presenca autenticavel (token social/HMAC), capa e nick server-authoritative.
* TOP TEMPO com teto por CONTA + HARDWARE + IP e anomalias.
* `hostguard.js` (bloqueio de host privado/porta nao-Minecraft) — falta aplicar no
  `server:status` do launcher (patch em `docs/INTERFACE-LAUNCHER-2026-10-01.md`).

## PENDENCIAS (para o dono)

1. **Publicar o codigo no GitHub.** O VPS NAO tem credencial de push. Copia
   segura em `/root/backups/seguranca-backend-2026-10-01/` (arquivos + patch).
   Numa maquina com credencial: aplicar o patch/arquivos, `git commit`, `git push`.
2. **Reconciliar o `main` do VPS com o `origin/main`** depois do push. Hoje o
   `main` local (`fb092d8`) NAO e ancestral de `origin/main` (`bbbfbac`), entao o
   auto-deploy nunca conseguia fast-forward e reiniciava o backend a cada 2 min
   (defeito corrigido em `/usr/local/bin/reality-auto-update`, backup do original
   em `/root/backups/reality-auto-update.orig-*`). Depois do push:
   `cd /opt/reality-backend && git fetch origin && git reset --hard origin/main`
   — ATENCAO: isso descarta o que estiver so na arvore local, por isso o item 1
   (publicar) vem ANTES. Só rode isso quando o `origin/main` tiver esse codigo.
3. **E-mail do certbot**: o certificado foi emitido com
   `--register-unsafely-without-email`. Rode
   `certbot update_account --email <email-do-dono>` para receber aviso de
   expiracao (renovacao automatica ja esta agendada).
4. **Dominio proprio (opcional)**: `api.realityclient.com` nao resolve hoje.
   Com o A record apontado para 16.5.7.132:
   `certbot --nginx -d api.realityclient.com` + ajustar `server_name` no
   `/etc/nginx/sites-available/reality-backend` + trocar a BASE URL do launcher.
5. **`GUARD_ADMIN_KEY` nao esta definida** no pm2: por isso `/api/guard/reports`
   responde 503 (proteção intencional). Se quiser ler os relatorios, defina a env.
6. **F17 no launcher**: sem o patch do item 5 da INTERFACE, o IPC `server:status`
   continua aceitando host privado (varredura da rede local do jogador).

## Regras que NAO podem regredir

Ver o skill `reality-backend-ops` (secções "Regras que NAO podem regredir").
