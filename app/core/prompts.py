"""Mensagem ÚNICA de integração de um sistema satélite com o APP CENTRAL
(ver build_integration_package). Fica aqui como texto puro (não dentro do
template Jinja) porque os JSONs de exemplo têm chaves {...} que colidiriam
com a sintaxe {{ }} do Jinja.

Princípio: o admin responde às perguntas no "Novo sistema" e cola UMA mensagem
na IA/dev do sistema. As decisões que antes viravam perguntas de ida e volta
já vêm tomadas aqui; a IA só devolve um relatório (POST /api/v1/apps/integration/report).
"""
from __future__ import annotations

STACK_LABELS = {
    "django": "Django (Python)",
    "fastapi": "FastAPI (Python)",
    "flask": "Flask (Python)",
    "node": "Node.js (Express/Nest/Fastify)",
    "php": "PHP (Laravel/outro)",
    "java": "Java / .NET",
    "outro": "outro / não sei",
}

STACK_HINTS = {
    "django": "Prefira a biblioteca já usada no projeto para OAuth (ex.: authlib/requests). Sessão: use o login nativo do Django (`login(request, user)`) após o upsert do usuário; guarde as permissions do token na sessão.",
    "fastapi": "Use authlib ou httpx. Guarde as permissions do token na sessão assinada (SessionMiddleware) e crie uma dependência `require_permission(code)`.",
    "flask": "Use authlib ou requests. Guarde `permissions` na `session` e crie um decorator `@requires(code)`.",
    "node": "Use `openid-client` ou fetch nativo. Guarde `permissions` na sessão e crie um middleware `requirePermission(code)`.",
    "php": "Use a biblioteca OAuth já presente (ex.: league/oauth2-client). Guarde `permissions` na sessão e centralize a checagem num helper/middleware.",
    "java": "Use a biblioteca OIDC do framework já usado (Spring Security OAuth2 Client / Microsoft.AspNetCore.Authentication.OpenIdConnect).",
    "outro": "Use a biblioteca OIDC/OAuth que o projeto já tiver; se não houver, implemente o Authorization Code + PKCE direto com HTTP.",
}

INTEGRATION_PACKAGE = """\
Integre o sistema "{NAME}" ao APP CENTRAL (login único + permissões). Esta
mensagem é COMPLETA: traz os dados, as decisões já tomadas e o formato do
relatório final. Execute tudo, não faça perguntas que estejam respondidas aqui;
só pare e pergunte se houver risco real de alguém perder acesso.

DADOS DA INTEGRAÇÃO
- client_id: {CLIENT_ID}
- client_secret: {CLIENT_SECRET}
  (guarde em variável de ambiente, ex.: CENTRAL_SSO_CLIENT_SECRET; NUNCA no
  código, no repositório, em log ou no resumo final)
- Endereço da Central: {BASE_URL_CENTRAL}
- Discovery OIDC: {BASE_URL_CENTRAL}/.well-known/openid-configuration
- Redirect URI (callback) cadastrado na Central, EXATAMENTE assim (inclusive a
  barra final, se houver):
{REDIRECT_URIS}
- Sistema: {NAME}{SYSTEM_EXTRA}
- Já tem usuários com poderes hoje (is_staff, roles, flags)? {HAS_LOCAL}

{STACK_BLOCK}DECISÕES JÁ TOMADAS (não pergunte)
1. Callback: crie uma rota PRÓPRIA para o login da Central (não misture com a
   rota da Microsoft/gov.br) e use exatamente a Redirect URI acima. Se o seu
   código precisar de outra, NÃO mude por conta própria: use a acima e liste
   a diferença em "central_requests" no relatório.
2. Permissões: um code por módulo/área protegida, no formato "recurso.acao",
   minúsculas (ex.: "docs.manage"). Cada flag booleana por usuário (is_staff,
   is_admin...) vira um code por área que ela protege, nunca um code único
   genérico tipo "sistema.editar" que o código não confira de verdade. Não
   invente permissão que não exista no código.
3. Quem entra por outro método (senha local, Microsoft SSO, gov.br) e não tem
   lista de permissões da Central fica com NENHUMA permissão de gestão (o
   acesso de leitura continua). Não crie plano B nem rotina de contingência
   para "a Central cair": se ela cair, todos os sistemas caem juntos, e isso
   é esperado.
4. Não mexa no painel técnico do framework (ex.: /admin/ do Django); ele não
   faz parte desta integração.
5. Ser administrador da Central NÃO dá nenhum acesso a este sistema: o token só
   traz as permissões concedidas explicitamente a cada pessoa NESTE sistema. Não
   trate "roles", "is_superuser" nem nada vindo da Central como admin local;
   admin deste sistema = ter a(s) permissão(ões) correspondente(s) na lista
   "permissions" (ex.: prefixo "admin_" = Super Admin deste sistema).
6. Nomes de pessoas vêm do cadastro da Central e são atualizados a cada login.
7. Se o seu ambiente bloquear (modo automático, aprovação) edições de
   autorização, NÃO contorne: pare, diga qual comando foi bloqueado e peça
   aprovação ao dono.

FASE 1 — NÃO DESTRUTIVA (faça tudo, publique, e só então vá à fase 2)
Nada local é apagado nesta fase.

Passo 0 — Procure no repositório se já existe fluxo de login contra este
mesmo APP CENTRAL (termos: "central", "sso", "oidc", "oauth", "callback"). Se
existir, AUDITE e COMPLETE (é comum já trocar o code mas ignorar o claim
"permissions"); não construa um segundo fluxo. Diga no relatório o que já
existia.

Passo 1 — Inventário: varra o código e liste TODA checagem de autorização real
(decorator, middleware, if de role/permissão, guard de rota, flag booleana).
Atribua os codes conforme a decisão 2.

Passo 2 — Cadastre as permissões na Central (uma chamada; repetível; só
cria/atualiza, nunca apaga):

curl -X POST {BASE_URL_CENTRAL}/api/v1/apps/permissions/sync \\
  -H "Content-Type: application/json" \\
  -d '{"client_id": "{CLIENT_ID}", "client_secret": "<o client_secret acima>",
       "permissions": [
         {"code": "contratos.assinar", "name": "Assinar contratos", "description": "Libera a assinatura"}
       ]}'

Passo 2b — {ACCESS_STEP}

Passo 3 — Login via OIDC Authorization Code + PKCE (S256): redirecione para
{BASE_URL_CENTRAL}/oauth/authorize e troque o "code" em POST
{BASE_URL_CENTRAL}/oauth/token. O id_token/userinfo trazem: sub, name, email,
"permissions" (lista de strings), "roles", "client_code". Todos devem ser
lidos e usados. A cada login faça upsert do usuário local (casa por "sub" ou
e-mail; cria se não existir, atualiza nome/e-mail se existir) e NUNCA recuse
o login por "usuário ainda não existe aqui". Substitua cada checagem de
autorização do inventário por uma verificação de string na lista "permissions"
do token, com os mesmos codes do passo 1.

Passo 3b — "Entrar com outra conta" (obrigatório): quem está logado na Central
(ex.: um admin) cai direto nesta conta e nunca consegue testar o sistema como
outro usuário. Na tela de login, ao lado do botão da Central, coloque o link
"Entrar com outra conta" apontando para a mesma rota de início do login com
?trocar=1. Com esse parâmetro, acrescente prompt=login&max_age=0 ao pedido de
autorização; a Central encerra a sessão dela e pede usuário e senha. O botão
normal continua com entrada direta.
{TENANT}
FASE 2 — LIMPEZA (SÓ depois de a Fase 1 estar publicada E de o passo 2b
retornar "grants_added" coerente; se não houver passo 2b, só depois do login
funcionando)
- Remova a tela/CRUD de usuários e qualquer tabela/campo local de role ou
  permissão. Mantenha só um registro mínimo de usuário (id, sub, nome, e-mail)
  para chaves estrangeiras.
- Não guarde senha nem grants de permissão localmente: a lista "permissions"
  do token é a fonte da verdade a cada login. Se a sessão local durar muito,
  revalide com POST {BASE_URL_CENTRAL}/api/v1/introspect (form: token,
  client_id, client_secret); a resposta traz active e permissions.
- Se o sistema não tinha "usuário ativo/inativo", agora precisa ter: usuário
  desativado na Central (active:false) não pode continuar entrando.
- NÃO apague nenhuma checagem sem correspondência conhecida na Central: pare,
  mantenha o controle e liste em "unmapped_checks".

RELATÓRIO FINAL (obrigatório — é isso que fecha a integração)
Ao terminar (ou ao travar), envie à Central:

curl -X POST {BASE_URL_CENTRAL}/api/v1/apps/integration/report \\
  -H "Content-Type: application/json" \\
  -d '{"client_id": "{CLIENT_ID}", "client_secret": "<o client_secret acima>",
       "status": "completed",
       "stack": "<linguagem/framework>",
       "had_previous_integration": false,
       "permissions": ["docs.manage"],
       "users_synced": 0,
       "login_done": true,
       "switch_account_link": true,
       "phase2_done": true,
       "redirect_uri_used": "<a redirect URI que o código realmente envia>",
       "unmapped_checks": [],
       "central_requests": ["o que precisa ser ajustado na Central, se algo"],
       "notes": "o que você não teve certeza e decidiu não mexer"}'

"status" é "completed", "partial" (faltou algo; explique em notes) ou
"blocked". Em "central_requests" liste TUDO que depende de alguém na Central
(ex.: cadastrar outra redirect URI, vincular cliente a um usuário). Se a lista
estiver vazia, a integração está encerrada.

Depois, responda no chat com um resumo curto: (a) o que já existia vs. o que
foi construído; (b) permissões cadastradas; (c) o passo a passo para eu testar
o login (e o "Entrar com outra conta"); (d) o conteúdo de "central_requests".
"""

ACCESS_STEP_WITH_USERS = """\
IMPORTE QUEM JÁ TEM ACESSO (obrigatório, ANTES de qualquer limpeza)
Envie e-mail + permissões de cada pessoa que hoje tem poderes (cada flag
antiga vira os codes das áreas que ela protegia). Quem não existe na Central é
criado sem senha e entra pelo login federado (casa por e-mail). Só concede,
nunca revoga. A resposta traz grants_added (confira: pessoas × codes) e
skipped_invalid_email (deve vir vazio). Se os dados de quem tem poder só
existirem no banco de produção, em que você não tem acesso, peça ao dono para
colar a lista e PARE a Fase 2 até recebê-la.

curl -X POST {BASE_URL_CENTRAL}/api/v1/apps/access/sync \\
  -H "Content-Type: application/json" \\
  -d '{"client_id": "{CLIENT_ID}", "client_secret": "<o client_secret acima>",
       "users": [
         {"email": "maria@empresa.com", "full_name": "Maria", "permissions": ["contratos.assinar"]}
       ]}'"""

ACCESS_STEP_NO_USERS = """\
NÃO SE APLICA: este sistema ainda não tem usuários com poderes locais.
Os acessos serão concedidos direto na Central. Pule este passo."""

TENANT_ADDENDUM = """\

MULTI-CLIENTE (este sistema atende vários clientes)
O token/userinfo traz o claim "client_code" (string ou null): use-o para
resolver a qual tenant/cliente vincular o usuário na primeira vez que ele
aparece. NUNCA recuse o login por "usuário ainda não existe aqui".
- "client_code" presente → vincule (ou crie, se não existir) o tenant com esse
  código e crie o vínculo (Membership/papel) do usuário com ele.
- "client_code" ausente e as "permissions" indicarem administrador global
  (prefixo "admin_") → Super Admin, sem tenant.
- "client_code" ausente e SEM sinal de admin global → configuração incompleta
  na Central: registre o login (upsert) sem Membership e liste a pessoa em
  "central_requests" ("vincular cliente a <e-mail>").
Não chame a Central a cada requisição: confie no token pela duração da sessão
e revalide via /api/v1/introspect só ao expirar ou antes de ação sensível.
"""


def build_integration_package(
    *,
    name: str,
    client_id: str,
    client_secret: str,
    central_url: str,
    redirect_uris: str,
    multi_client: bool,
    base_url: str = "",
    stack: str = "",
    description: str = "",
    has_local_access: bool = True,
) -> str:
    """Mensagem única, já preenchida, que o admin manda ao dono do sistema novo."""
    central = central_url.rstrip("/")
    uris = [u.strip() for u in redirect_uris.replace(",", "\n").splitlines() if u.strip()]
    uris_block = "\n".join(f"    {u}" for u in uris) or (
        "    (ainda não cadastrada: use a rota de callback que você criar e informe-a\n"
        "    em \"central_requests\" para ser cadastrada na Central)"
    )

    extra = ""
    if base_url.strip():
        extra += f"\n- Endereço do sistema: {base_url.strip()}"
    if description.strip():
        extra += f"\n- O que faz: {description.strip()}"
    if multi_client:
        extra += "\n- Atende vários clientes: SIM (veja MULTI-CLIENTE abaixo)"

    stack_block = ""
    if stack in STACK_LABELS:
        stack_block = (
            f"STACK: {STACK_LABELS[stack]}. {STACK_HINTS[stack]}\n"
            "Confirme a stack olhando o repositório; se for diferente, siga o que o repositório usa.\n\n"
        )

    # Substituição simples (não .format): o texto tem chaves de JSON.
    access_step = ACCESS_STEP_WITH_USERS if has_local_access else ACCESS_STEP_NO_USERS
    out = INTEGRATION_PACKAGE
    for key, value in {
        "{ACCESS_STEP}": access_step,
        "{TENANT}": TENANT_ADDENDUM if multi_client else "",
        "{STACK_BLOCK}": stack_block,
        "{SYSTEM_EXTRA}": extra,
        "{HAS_LOCAL}": "SIM (passo 2b obrigatório)" if has_local_access else "NÃO (pule o passo 2b)",
        "{REDIRECT_URIS}": uris_block,
        "{NAME}": name,
        "{CLIENT_ID}": client_id,
        "{CLIENT_SECRET}": client_secret,
        "{BASE_URL_CENTRAL}": central,
    }.items():
        out = out.replace(key, value)
    return out
