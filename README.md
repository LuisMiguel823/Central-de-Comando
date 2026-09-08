# Central de Comando — APP CENTRAL (SSO / IAM)

Sistema central de **login único, permissões e auditoria** para um conjunto de
aplicações satélite (APP 1, APP 2, APP 3...), com **federação de identidade
gov.br**. É a tradução em código do quadro branco "Atricon PM":

```
                 ┌─────────────────┐   ── Clientes
   LOGIN ───────▶│   APP CENTRAL   │── ── Operadores
   PERMISSÃO     │  (este projeto) │   ── Apps (permissões)
   LOG (entrou/  └───────┬─────────┘
       saiu/perm)        │  emite tokens OIDC
        ┌────────────────┼────────────────┐
     ┌──▼──┐          ┌──▼──┐          ┌──▼──┐
     │APP 1│          │APP 2│ (www)    │APP 3│
     └─────┘          └─────┘          └─────┘

   gov.br / e-CAC ──▶ Login Único ──▶ APP CENTRAL confia na identidade
```

## O que já vem pronto

| Área | Entregue |
|------|----------|
| **Autenticação** | Login local (usuário/senha, bcrypt) + sessão em cookie assinado |
| **Federação gov.br** | Fluxo OIDC completo (`/auth/govbr/login` → `/auth/govbr/callback`), auto-provisionamento opcional de operador |
| **Federação Login Único municipal** | Fluxo Neomind Fusion WSAuth (`WSAuthInit_edu` → redirect → `WSAuthVerify_edu`, consulta única), instância por câmara, checagem de nível da conta |
| **SSO Microsoft (Entra ID)** | OAuth2 Authorization Code na mão (sem `msal`/`authlib`), troca `code` → `access_token` → Graph `/me`; autentica só operador **já cadastrado** (casa por e-mail), não provisiona; `state` na sessão contra CSRF |
| **Provedor OIDC** | `/.well-known/openid-configuration`, `/oauth/authorize`, `/oauth/token` (authorization_code + refresh_token + PKCE), `/oauth/userinfo`, `/oauth/jwks.json` — os apps satélite fazem "Entrar com APP CENTRAL" |
| **Cadastros** | Clientes (com plano Bronze/Prata/Ouro/Diamante), Operadores, Aplicações |
| **Permissões** | Catálogo por app + concessão por operador; admin herda tudo |
| **Auditoria** | `entrou / saiu / login falhou / permissão +N -N / CRUD` com ator, IP, user-agent, filtros e paginação |
| **API REST** | `/api/v1/me`, `/api/v1/introspect` (RFC 7662), `/api/v1/apps/{slug}/my-permissions`, leitura administrativa |
| **UI** | Dashboard com KPIs + tema claro/escuro (lateral azul-marinho fixa, cyan de destaque, `dark-mode.css` interceptando as classes Tailwind) |

## Stack

FastAPI · SQLAlchemy 2 · Alembic · MySQL 8 · Jinja2 · Tailwind (CDN) · Authlib

---

## Subir com Docker (recomendado)

```bash
cp .env.example .env          # ajuste SECRET_KEY e, se for usar, as chaves gov.br
docker compose up --build
```

- App: http://localhost:8000
- Swagger: http://localhost:8000/docs
- MySQL: `localhost:3306` (banco `central_comando`)

O container do app espera o MySQL, roda o **seed** (só se o banco estiver vazio)
e sobe o Uvicorn com reload. Login inicial: **admin / admin123**
(veja `BOOTSTRAP_ADMIN_*` no `.env`).

## Rodar local sem Docker

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
# source .venv/bin/activate                          # Linux/Mac
pip install -r requirements.txt

# suba um MySQL (pode ser só o serviço db do compose):
docker compose up -d db

cp .env.example .env
python -m scripts.seed                                # cria admin + dados demo
uvicorn app.main:app --reload
```

## Migrations (produção)

Em dev, `AUTO_CREATE_TABLES=true` cria as tabelas no boot. Em produção, desligue
isso e use Alembic:

```bash
alembic revision --autogenerate -m "inicial"
alembic upgrade head
```

---

## Como um app satélite se integra

1. No painel, **Aplicações → Nova aplicação**. Guarde o `client_id` e o
   `client_secret` (mostrado uma única vez) e cadastre o `redirect_uri`.
2. No app satélite, use qualquer client OIDC apontando para:
   - discovery: `http://localhost:8000/.well-known/openid-configuration`
3. Fluxo: redirecione o usuário para `/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid%20profile%20email&state=...`
4. Troque o `code` em `POST /oauth/token`. O `id_token` / `userinfo` trazem:

```json
{
  "sub": "42",
  "name": "Fulana de Tal",
  "email": "fulana@camara.gov.br",
  "permissions": ["protocolo.ler", "protocolo.criar"],
  "roles": [],
  "client_code": "CMSPA"
}
```

5. Para validar um access token depois, o app chama
   `POST /api/v1/introspect` (form: `token`, `client_id`, `client_secret`).

## Configurar o gov.br

No `.env`:

```
GOVBR_ENABLED=true
GOVBR_ISSUER=https://sso.staging.acesso.gov.br     # homologação
GOVBR_CLIENT_ID=<fornecido pelo gov.br>
GOVBR_CLIENT_SECRET=<fornecido pelo gov.br>
GOVBR_REDIRECT_URI=http://localhost:8000/auth/govbr/callback
```

O `GOVBR_REDIRECT_URI` precisa estar homologado junto ao gov.br. Sem
`CLIENT_ID/SECRET` o botão "Entrar com gov.br" fica oculto e o resto do sistema
funciona normalmente com login local.

## Configurar o Login Único municipal (Neomind Fusion)

Fluxo **próprio da prefeitura**, não é OIDC. Três passos:

1. `GET {base}/WSAuthInit_edu.rule?sys={sys}&redirect={callback}` → JSON `{location, token, expires_in}`
2. Redireciona o navegador para `location`; o usuário loga no portal da prefeitura
3. `GET {base}/WSAuthVerify_edu.rule?sys={sys}&token={token}` → nome, e-mail, CPF, foto, nível da conta (**consulta única por token!**)

No `.env` (valor global):

```
LOGINUNICO_ENABLED=true
LOGINUNICO_BASE_URL=https://loginunico.cabofrio.rj.gov.br/loginunico
LOGINUNICO_SYS=SLU
LOGINUNICO_CALLBACK_URL=http://localhost:8000/auth/loginunico/callback
LOGINUNICO_MIN_LEVEL=1            # nível mínimo (1/2/3) exigido para entrar
```

O `LOGINUNICO_CALLBACK_URL` é o `redirect` enviado no passo 1 — precisa estar
liberado junto à prefeitura. Como **cada câmara tem sua própria instância**, no
cadastro de **Clientes** você pode preencher *"Login Único — URL base"* e *"sys"*
para sobrescrever o global; nesse caso o link fica
`/auth/loginunico/login?cliente=CMCABO`. O seed já traz a câmara `CMCABO`
(Cabo Frio) com a instância preenchida como exemplo.

Implementação em `app/services/loginunico.py` (o `normalize_user` tolera
variações de maiúsculas/minúsculas nas chaves do JSON, que mudam entre
instâncias do Fusion). Rotas em `app/routers/auth.py`
(`/auth/loginunico/login` e `/auth/loginunico/callback`). O token da consulta
única fica na sessão e há trava contra reconsulta (`lu_verified`).

## Configurar o SSO Microsoft (Entra ID / Azure AD)

OAuth2 **Authorization Code**, implementado com `httpx` puro — sem `msal` nem
`authlib`. Troca o `code` por `access_token` e chama o Graph `/me`, então não
precisa validar assinatura de ID token na mão.

No **App Registration** (portal.azure.com → Entra ID → App registrations):
- *Redirect URI* (tipo Web) = exatamente o valor de `MICROSOFT_REDIRECT_URI`
  (esquema `https://` incluso — a Azure compara byte a byte)
- *Certificates & secrets* → novo client secret
- *API permissions* → Microsoft Graph → `User.Read` (delegated)

No `.env`:

```
MICROSOFT_CLIENT_ID=<Application (client) ID>
MICROSOFT_CLIENT_SECRET=<client secret>
MICROSOFT_TENANT_ID=<Directory (tenant) ID>
MICROSOFT_REDIRECT_URI=https://seu-dominio.com/auth/microsoft/callback
```

Fluxo: `/auth/microsoft/login` gera um `state` aleatório (na sessão, anti-CSRF)
e redireciona para `login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`.
`/auth/microsoft/callback` confere o `state`, troca o `code` em `/oauth2/v2.0/token`,
lê o e-mail do Graph (`mail` ou `userPrincipalName`) e **procura um operador já
cadastrado com esse e-mail** — não cria usuário novo. Achou e ativo → sessão
normal + auditoria (`auth.login`, "Login via Microsoft (SSO)"). Não achou →
volta ao login com erro e registra `auth.microsoft_denied`.

Login por senha continua funcionando em paralelo. Os 3 valores vazios escondem
o botão "Entrar com Microsoft".

> **SSO real entre APP CENTRAL e MILVUS** (um login abre os dois): usar o
> **mesmo App Registration** (mesmo `CLIENT_ID`/`TENANT_ID`) nos dois sistemas.

---

## Estrutura

```
app/
  config.py          # settings via .env
  database.py         # engine + Session + Base
  models/             # Client, User, Application, Permission, OAuth*, AuditEvent
  core/               # security (hash/JWT/RSA), deps (auth), audit, templating
  services/           # govbr (OIDC), loginunico (Fusion WSAuth), microsoft (Entra ID), oidc (provedor), permissions
  routers/            # auth, oauth (provedor), api (REST), web_pages (UI)
  templates/ static/  # Jinja2 + Tailwind + dark-mode.css + theme.js
scripts/
  seed.py             # admin + câmaras do quadro + apps demo
  wait_for_db.py      # usado pelo compose
migrations/           # Alembic
```

## Padrão visual

- **Menu lateral**: gradiente `blue-900 → cyan-900` **fixo** nos dois temas,
  borda `cyan-700/50`, item ativo `cyan-700/30` (ou `cyan-500/15` no Dashboard),
  rótulos de seção em `cyan-400`. O `dark-mode.css` **não toca** na lateral.
- **Conteúdo**: tema claro `slate-50 / slate-700 / bg-white`; o `dark-mode.css`
  intercepta as mesmas classes quando `<html>` tem `.dark` — superfícies
  escurecem (`#0f172a`, `#1e293b`), textos clareiam (`#e2e8f0`, `#cbd5e1`),
  tints viram versão escura dessaturada. Gradiente `cyan-600 → blue-600` dos
  botões **não muda**.
- Toggle em `theme.js`, persistido em `localStorage['cc-theme']`.

---

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
