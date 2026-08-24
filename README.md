# Reality Client Backend

Backend mínimo pra o launcher puxar **config remota**, **updates**, **criadores** e **códigos de resgate**.

Quando você muda o manifesto no servidor, **todos os PCs** recebem no próximo abrir do launcher (ou ao checar update).

## Rodar local

```bash
cd backend
npm install
ADMIN_TOKEN=segredo123 npm start
```

Abre em `http://localhost:3000`.

Teste:
```bash
curl http://localhost:3000/api/manifest
curl http://localhost:3000/health
```

## Deploy (Render.com — grátis)

1. Suba esta pasta `backend/` num repositório GitHub
2. [Render](https://render.com) → New → Web Service → conecte o repo
3. Root Directory: `backend`
4. Build: `npm install`
5. Start: `npm start`
6. Environment:
   - `ADMIN_TOKEN` = um token aleatório forte com pelo menos 24 caracteres
   - `CORS_ORIGINS` = opcional; origens do painel administrativo separadas por vírgula
   - `PORT` = (Render define sozinho)
7. Copie a URL (ex: `https://reality-client-backend.onrender.com`)

## Conectar no launcher

Em `src/backendApi.js`:

```js
const BACKEND_URL = 'https://SUA-URL.onrender.com';
```

Em Configurações / store, o `updateFeedUrl` pode ser:

```
https://SUA-URL.onrender.com/api/update
```

## Atualizar config de todos os players

```bash
curl -X POST https://SUA-URL/api/admin/manifest \
  -H "Content-Type: application/json" \
  -H "x-admin-token: SEU_TOKEN" \
  -d '{
    "discord": {
      "reality": "https://discord.gg/JJHScuCf8y",
      "kowa": "https://discord.gg/6jRn5jKCnd"
    },
    "announcement": {
      "enabled": true,
      "title": "Novidade",
      "message": "Capas e skins offline ativas!"
    }
  }'
```

Publicar nova versão do launcher:
1. Faça `npm run build:win`
2. Hospede o `.exe` em uma origem HTTPS confiável.
3. Gere o SHA-256 do instalador (`certutil -hashfile RealityClientSetup.exe SHA256` no Windows).
4. Atualize o manifesto:

```bash
curl -X POST https://SUA-URL/api/admin/launcher \
  -H "Content-Type: application/json" \
  -H "x-admin-token: SEU_TOKEN" \
  -d '{
    "latestVersion": "1.0.1",
    "downloadUrl": "https://link-do-seu-exe",
     "notes": "Correção de capas + mods ocultos",
     "sha256": "SHA256_EM_HEX",
     "size": 123456789,
     "mandatory": false
  }'
```

O launcher baixa a atualização em um arquivo temporário, valida tamanho e
SHA-256 quando informados, renomeia o arquivo de forma atômica e instala
automaticamente no Windows. Se o Minecraft estiver aberto, a instalação aguarda
o encerramento do jogo. Para macOS/Linux, publique também os pacotes em
`platforms.mac` e `platforms.linux`; a instalação automática do pacote NSIS é
somente para Windows.

Para publicar uma nova versão dos termos, envie um objeto `terms` com uma nova
`version`, `title`, `effectiveAt` e, opcionalmente, `sections` (cada seção tem
`title` e `paragraphs`). A nova versão invalida o aceite anterior e aparece
antes do uso do launcher.

## O que NÃO sincroniza automaticamente

- Código-fonte do Electron (precisa build + update do exe)
- Skins/capas **pessoais** de cada usuário (ficam no PC dele)
- Contas offline de cada um

Nunca passe o token administrativo na query string. Use o header
`x-admin-token` ou `Authorization: Bearer`.

O que **sincroniza**: Discord, anúncios, features, criadores, códigos, link de update do launcher.

## Código de lançamento `RELEASE`

O manifesto incluído já publica o código `RELEASE`. Ele desbloqueia apenas o
tema visual exclusivo `reality-aurora` e o selo **Membro do Reality** no
launcher, sem criar capa, mensagem promocional ou entrada nos créditos. O código é ilimitado em
quantidade de jogadores, mas cada nome de conta só pode resgatá-lo uma vez. O
backend guarda apenas um hash SHA-256 do nome para impedir duplicidade sem
salvar o nome da conta no histórico de resgates.

Para códigos limitados, defina `usesLeft` como um número:

```json
{
  "VIP-2026": {
    "role": "Apoiador VIP",
    "cape": "creator.png",
    "usesLeft": 100,
    "expiresAt": "2026-12-31T23:59:59.000Z",
    "message": "Recompensa VIP desbloqueada!"
  }
}
```

O endpoint público aplica limite de tentativas por endereço, valida expiração,
evita resgates duplicados e serializa os resgates para reduzir o risco de duas
requisições consumirem o mesmo uso. Para produção com múltiplas instâncias,
migre os códigos para um banco com transação/lock distribuído.
