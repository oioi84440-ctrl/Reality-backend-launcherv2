# INTERFACE — o que o LAUNCHER precisa saber (round de seguranca 2026-10-01)

Este arquivo e o contrato de interface entre o BACKEND (ja em producao) e o
LAUNCHER. Nada aqui exige mudar o launcher AGORA para continuar funcionando: os
itens estao marcados como **OBRIGATORIO** (para fechar o achado) ou
**RECOMENDADO**.

---

## 1. F01 — URL do backend agora tem TLS

* **Nova BASE URL (producao, HTTPS): `https://16-5-7-132.sslip.io`**
  * Certificado Let's Encrypt valido (chains OK, HSTS ligado).
  * `http://16-5-7-132.sslip.io` (porta 80) → **301** para HTTPS.
  * `http://16.5.7.132:3000` **continua funcionando** em HTTP puro (compat da
    transicao). Nada quebra se o launcher nao mudar hoje.
* **OBRIGATORIO (quando der)**: trocar a constante em `src/backendApi.js`
  (`http://16.5.7.132:3000` → `https://16-5-7-132.sslip.io`) e remover a
  excecao de "IP privado" em `src/updateChecker.js` (`host === '16.5.7.132'`),
  que hoje libera o feed atual de exigir HTTPS.
* **Pendencia de dono de produto**: `16-5-7-132.sslip.io` e um DNS publico
  wildcard (sslip.io) apontando para 16.5.7.132 — funciona sem comprar nada. Um
  dia, com dominio proprio (ex.: `api.realityclient.com`), e so apontar o A
  record e rodar `certbot --nginx -d api.realityclient.com` no VPS.

## 2. F02 — assinatura do feed de update (Ed25519)

O `GET /api/update` agora devolve, alem dos campos de sempre:

```
{
  "version": "...", "url": "...", "sha256": "...", "size": 123,
  "sig":     "<base64, 64 bytes>",       // assinatura detached
  "sigAlg":  "ed25519",
  "sigKeyId":"d88166de343ae7a4"
}
```

* **Payload canonico** (UTF-8, exatamente nesta ordem e separadores):
  `"<version>|<url>|<sha256>|<size>"` — onde `size` e o inteiro decimal sem
  separador (`Number(launcher.size) || 0`).
* **Chave publica** (32 bytes RAW, base64) — **embutir no app**:

  ```
  1ucmqVV5+kVn2qC1qp3kzwNnKSMAx5E8McMhmbwATa8=
  ```

  keyId `d88166de343ae7a4`. Tambem disponivel em `GET /api/pubkey`.
* **Assinatura tambem vem** no header `x-reality-manifest-sig` e como arquivo
  detached em `GET /api/manifest.sig` (texto puro, ao lado do `manifest.json`).
* **Objeto SPKI DER** da chave = `302a300506032b6570032100` + os 32 bytes RAW.
* Exemplo de verificacao (Node, mesma logica usada nos testes):

```js
const crypto = require('crypto');

const PUB_B64 = '1ucmqVV5+kVn2qC1qp3kzwNnKSMAx5E8McMhmbwATa8='; // embutir no app
const pubDer  = Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'),
  Buffer.from(PUB_B64, 'base64')
]);
const publicKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });

async function checkForUpdate(feedUrl) {
  const feed = await (await fetch(feedUrl, { headers: { Accept: 'application/json' } })).json();
  const payload = [String(feed.version), String(feed.url), String(feed.sha256), String(feed.size)].join('|');
  const ok = crypto.verify(
    null,
    Buffer.from(payload, 'utf-8'),
    publicKey,
    Buffer.from(feed.sig || '', 'base64')
  );
  if (!ok) throw new Error('update_feed_signature_invalid'); // NAO baixar, NAO instalar
  return feed; // version/url/sha256/size/notes...
}
```

* **OBRIGATORIO**: recusar (nao baixar/instalar) quando `sig` estiver ausente ou
  invalido. Sem isso o F02 continua aberto no lado cliente.
* **RECOMENDADO**: allowlist do host de download (o proprio
  `github.com/oioi84440-ctrl/...` ou o dominio do projeto) e confirmacao do
  usuario no primeiro install vindo de um host novo.

## 3. F07 — presenca autenticada (opcional hoje, recomendado)

O `POST /api/presence/heartbeat` aceita tres formas, em ordem de forca:

1. **Token social (melhor)** — `Authorization: Bearer <socialToken>`:
   o servidor deriva **nick da conta** e **amarra o uuid a conta** no primeiro
   heartbeat verificado. Mandar uuid/nick de outra pessoa → `403 identity_mismatch`.
   Habilitar no `src/presenceApi.js` (o token ja esta no main):
   ```js
   const headers = { 'Content-Type': 'application/json' };
   if (socialToken) headers.Authorization = 'Bearer ' + socialToken;   // <-- NOVO
   ```
2. **HMAC por dispositivo** (para o mod in-game, que nao tem token):
   `X-Reality-Presence-Sig` + `X-Reality-Presence-Ts`, onde
   `sig = HMAC-SHA256(SEGREDO, normalizeUuid(uuid) + '|' + name + '|' + capeId + '|' + floor(ts/1000))`.
   O segredo e o `PRESENCE_HMAC_SECRET` do backend (hoje nao definido — falar com
   o dono antes de ligar).
3. **Anonimo (como e hoje)** — continua respondendo `200`, mas entra no indice
   com `verified: false` e com regras:
   * nao pode **renomear** entrada existente (`403 name_locked`);
   * nao pode reescrever entrada **verificada** (`401 verified_identity_requires_token`);
   * capa do sistema (codigo/loja/travada) so entra se a **conta possui**
     (`capeIgnored: true` quando nao possui);
   * 1 heartbeat por uuid a cada 4s e teto por IP.

Resposta agora: `{ ok, verified, source, uuid, name, capeId, capeIgnored }`.
`GET /api/presence/online` e `GET /api/presence` ganharam `verified` por jogador
(e `?verified=1` filtra so os autenticados).

## 4. F17 — bloqueio de host privado no `server:status` (LAUNCHER)

O guard canonico esta em `hostguard.js` (neste repo). No `main.js` do launcher,
substituir o handler por:

```js
const { isAllowedMinecraftTarget } = require('./hostguard'); // copiar o arquivo

ipcMain.handle('server:status', async (_e, address) => {
  const check = isAllowedMinecraftTarget(String(address || '').trim());
  if (!check.ok) return { online: false, error: check.error };   // private_host_blocked / port_not_minecraft
  try {
    return await fetchServerStatus(check.host + ':' + check.port);
  } catch (e) {
    return { online: false, error: e.message || String(e) };
  }
});
```

O mesmo modulo ja roda no backend e esta exposto para conferencia em
`POST /api/admin/validate-host { address }` (admin).

## 5. Outras mudancas de resposta (aditivas, sem quebra)

* `/api/coins/earn|spend`: campos de valor no body (`amount`, `coins`, `price`,
  `saldo`, ...) sao **ignorados** e registrados no log — o preco vem do catalogo
  do servidor (F09).
* `/api/social/*`: token **so** via `Authorization: Bearer`. Token no body ou na
  query vira `400 token_in_body_not_allowed` (o launcher ja usa o header).
