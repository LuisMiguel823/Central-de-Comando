"""Textos usados na mensagem de integração de um sistema satélite com o
APP CENTRAL (ver build_integration_package). Ficam aqui como texto puro (não
dentro do template Jinja) porque o JSON de exemplo tem chaves {...} que colidiriam
com a sintaxe {{ }} do Jinja.
"""
from __future__ import annotations

IMPLEMENTATION_PROMPT = """\
Este sistema vai parar de gerenciar usuários/permissões localmente. A partir de
agora, login e permissionamento vêm 100% do "APP CENTRAL" via OIDC.

client_id: {CLIENT_ID}
client_secret: {CLIENT_SECRET}
issuer/discovery: {BASE_URL_CENTRAL}/.well-known/openid-configuration

PASSO 0 — OBRIGATÓRIO antes de escrever qualquer código: procure no repositório
se já existe uma rota/fluxo de login contra este mesmo APP CENTRAL (termos como
"central", "sso", "oidc", "oauth", "callback"). NÃO construa um segundo fluxo de
login do zero se já existir um — nesse caso, seu trabalho é AUDITAR e COMPLETAR
o que já existe (é comum ele já trocar o "code" e ler o userinfo, mas ignorar o
claim "permissions" — se for esse o caso, o ajuste é bem menor do que refazer
tudo). Me diga explicitamente, no resumo final, se encontrou algo assim e o que
já funcionava antes da sua mudança.

Depois do passo 0, garanta que o sistema (construindo do zero OU completando o
que já existe) cumpre TODOS os itens abaixo — não é opcional escolher alguns:

1. Login via OIDC Authorization Code + PKCE contra o APP CENTRAL, trocando o
   "code" em POST {BASE_URL_CENTRAL}/oauth/token. O id_token / userinfo trazem: sub, name,
   email, "permissions" (lista de strings), "roles", "client_code" — todos eles
   precisam ser efetivamente lidos e usados, nenhum pode ficar recebido e ignorado.

2. Para CADA checagem de autorização que hoje existe no código (decorators,
   middlewares, if de role/permissão, guard de rota, flags booleanas por
   usuário), substitua por uma verificação de string dentro da lista
   "permissions" recebida do token — use exatamente os mesmos codes já
   levantados no inventário anterior (não troque os nomes, não abrevie, não
   traduza).

3. Remova a tela/CRUD de Usuários e qualquer tabela/campo local de "role" ou
   "permissão" (incluindo dicts/colunas de permissão por usuário). Mantenha só
   um registro local mínimo de usuário (id interno, sub, nome, email) para
   chaves estrangeiras de outras entidades — populado por upsert no login
   (casa por "sub" ou e-mail; cria se não existir, atualiza se existir).

4. Não guarde senha nem grants de permissão localmente — a lista "permissions"
   do token é a fonte da verdade a cada login. Se a sessão local durar muito
   tempo sem novo login, revalide com POST {BASE_URL_CENTRAL}/api/v1/introspect (form:
   token, client_id, client_secret) antes de confiar numa permissão sensível.

5. Se o sistema hoje não tem campo de "usuário ativo/inativo" pra revogar
   acesso sem excluir o cadastro, isso agora É um requisito: um usuário
   desativado no APP CENTRAL não pode continuar acessando aqui. Descreva no
   resumo como isso ficou resolvido.

6. NÃO apague nenhuma checagem de autorização sem ter certeza de que ela
   corresponde a uma permissão já cadastrada no APP CENTRAL — se encontrar
   checagem sem correspondência conhecida, pare, NÃO remova o controle, e
   liste isso no resumo pra eu decidir.

7. Não desative nenhum outro método de login que ainda esteja em uso (ex.:
   Microsoft SSO, gov.br) só por causa desta tarefa — a substituição é apenas
   do controle de acesso local, os outros federations continuam funcionando
   em paralelo até segunda ordem.

No final, devolva um resumo objetivo com: (a) se já existia integração prévia
e o que foi completado nela vs. construído do zero; (b) toda checagem de
autorização que ficou sem permissão correspondente; (c) qualquer coisa que você
não teve certeza e decidiu não mexer.
"""

INTEGRATION_PACKAGE = """\
Preciso integrar o sistema "{NAME}" ao APP CENTRAL (login único + permissões).
Siga os passos na ordem. Tudo que você precisa está nesta mensagem.

DADOS DA INTEGRAÇÃO
- client_id: {CLIENT_ID}
- client_secret: {CLIENT_SECRET}   (guarde em variável de ambiente; NUNCA no código/repositório)
- Endereço da Central: {BASE_URL_CENTRAL}
- Discovery OIDC: {BASE_URL_CENTRAL}/.well-known/openid-configuration
- Rota de callback do login (redirect URI): {REDIRECT_URIS}

PASSO 1 — INVENTÁRIO DE PERMISSÕES
Varra o código e liste TODA checagem de autorização real (decorator, middleware,
if de role/permissão, guard de rota, flag booleana por usuário). Dê a cada uma um
code estável no formato "recurso.acao" (ex.: "contratos.assinar"), mantendo a
convenção que o código já usa, se houver. Não invente permissões que não existem
no código. Se o sistema não controla nada por usuário, a lista fica vazia.

PASSO 2 — CADASTRAR AS PERMISSÕES NA CENTRAL (automático, uma chamada)
Envie a lista do passo 1 para a Central. Pode ser repetido quantas vezes quiser:
só cria ou atualiza, nunca apaga nada.

curl -X POST {BASE_URL_CENTRAL}/api/v1/apps/permissions/sync \\
  -H "Content-Type: application/json" \\
  -d '{"client_id": "{CLIENT_ID}", "client_secret": "<o client_secret acima>",
       "permissions": [
         {"code": "contratos.assinar", "name": "Assinar contratos", "description": "Libera a assinatura"}
       ]}'

A resposta traz quantas permissões foram criadas/atualizadas. Depois disso o
administrador da Central já consegue conceder cada permissão aos usuários.

PASSO 2b — IMPORTAR QUEM JÁ TEM ACESSO (automático, uma chamada)
Se o sistema já tem usuários com poderes (is_staff, roles, flags), NÃO peça
cadastro manual: envie e-mail + permissões de cada um. Quem não existe na
Central é criado sem senha e entra pelo login federado (casa por e-mail).
Só concede, nunca revoga. Rode ANTES de apagar os dados locais de permissão.

curl -X POST {BASE_URL_CENTRAL}/api/v1/apps/access/sync \\
  -H "Content-Type: application/json" \\
  -d '{"client_id": "{CLIENT_ID}", "client_secret": "<o client_secret acima>",
       "users": [
         {"email": "maria@empresa.com", "full_name": "Maria", "permissions": ["contratos.assinar"]}
       ]}'

PASSO 3 — LOGIN E CONTROLE DE ACESSO VIA CENTRAL
{IMPLEMENTATION}
{TENANT}
No final, devolva um resumo objetivo com: (a) a lista de permissões cadastradas
no passo 2; (b) se já existia integração prévia e o que foi completado vs.
construído do zero; (c) qualquer checagem que ficou sem permissão correspondente;
(d) qualquer coisa de que você não teve certeza e decidiu não mexer.
"""


def build_integration_package(
    *,
    name: str,
    client_id: str,
    client_secret: str,
    central_url: str,
    redirect_uris: str,
    multi_client: bool,
) -> str:
    """Mensagem única, já preenchida, que o admin manda ao dono do sistema novo."""
    central = central_url.rstrip("/")
    implementation = (
        IMPLEMENTATION_PROMPT.replace("{CLIENT_ID}", client_id)
        .replace("{CLIENT_SECRET}", client_secret)
        .replace("{BASE_URL_CENTRAL}", central)
        .replace(
            "use exatamente os mesmos codes já\n   levantados no inventário anterior",
            "use exatamente os mesmos codes do\n   passo 1 (já cadastrados no passo 2)",
        )
    )
    tenant = (
        "\n" + TENANT_PROVISIONING_ADDENDUM.replace("{BASE_URL_CENTRAL}", central)
        if multi_client
        else ""
    )
    # Substituição simples (não .format): o texto tem chaves de JSON.
    out = INTEGRATION_PACKAGE
    for key, value in {
        "{IMPLEMENTATION}": implementation,
        "{TENANT}": tenant,
        "{NAME}": name,
        "{CLIENT_ID}": client_id,
        "{CLIENT_SECRET}": client_secret,
        "{BASE_URL_CENTRAL}": central,
        "{REDIRECT_URIS}": redirect_uris.strip().replace("\n", " , ") or "(a definir)",
    }.items():
        out = out.replace(key, value)
    return out


# Complemento opcional — cole junto com o IMPLEMENTATION_PROMPT quando o
# sistema satélite for multi-tenant (precisa saber a QUAL cliente/tenant
# vincular o usuário no primeiro login) e você quer que o cadastro local
# vire 100% automático, sem passo manual algum.
TENANT_PROVISIONING_ADDENDUM = """\
Sobre o registro local mínimo do passo 3: NUNCA recuse o login por "usuário
ainda não existe aqui" — sempre faça upsert (cria se não existir, atualiza se
existir), casando por "sub" (ou e-mail, se o provedor não mandar "sub"
estável). O token/userinfo do APP CENTRAL traz um claim "client_code"
(string ou null) — use-o pra resolver automaticamente a qual tenant/cliente
vincular esse usuário na primeira vez que ele aparece:

- "client_code" presente → vincule (ou crie, se ainda não existir aqui) o
  tenant correspondente a esse código, e crie o vínculo (Membership/papel)
  do usuário com ele.
- "client_code" ausente e o claim "roles" ou as "permissions" indicarem
  administrador global (ex.: presença de alguma permissão prefixada
  "admin_") → trate como Super Admin, sem tenant nenhum.
- "client_code" ausente e SEM sinal de administrador global → é uma
  configuração incompleta do lado do APP CENTRAL (operador sem cliente
  vinculado lá), não um caso a resolver adivinhando aqui: registre o login
  mesmo assim (upsert do registro mínimo), mas sem Membership nenhum, e
  deixe claro no resumo final que esse usuário precisa ser vinculado a um
  tenant manualmente ou ter o "Cliente" dele corrigido no APP CENTRAL.

Sobre confiar no token: NÃO faça uma chamada ao APP CENTRAL a cada
requisição do usuário — confie no id_token/access_token (e na lista
"permissions" nele) pela duração da sessão local, e só revalide via
POST {BASE_URL_CENTRAL}/api/v1/introspect quando o token expirar ou antes de uma ação
especialmente sensível (ex.: excluir dado, exportar relatório com PII).
"""
