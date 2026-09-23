"""Prompts prontos para copiar/colar na IA que cuida do código de um sistema
satélite — usados para descobrir e depois integrar permissões via OIDC com o
APP CENTRAL. Ficam aqui como texto puro (não dentro do template Jinja) porque
o JSON de exemplo tem chaves `{...}` que colidiriam com a sintaxe `{{ }}` do
Jinja se estivessem embutidas direto no .html.
"""
from __future__ import annotations

DISCOVERY_PROMPT = """\
Você está trabalhando no código deste projeto, que vai se autenticar via SSO/OIDC
contra um provedor central chamado "APP CENTRAL" (login único, permissões e
auditoria). Preciso que você faça uma varredura COMPLETA e LITERAL deste
repositório — nada de suposição ou "geralmente sistemas assim têm X" — e me
devolva SOMENTE um JSON (sem comentários, sem texto antes/depois, sem markdown
de code fence) com o seguinte formato exato:

{
  "app": {
    "name": "<nome amigável do sistema, ex: 'Milvus Atendimento'>",
    "slug": "<slug curto, minúsculo, sem espaço, ex: 'milvus'>",
    "base_url": {
      "dev": "<url local de dev, ex: http://localhost:3000, ou null>",
      "staging": "<url de homologação, ou null>",
      "prod": "<url de produção, ou null>"
    },
    "redirect_uris": {
      "dev": "<url completa da rota de callback OIDC em dev, ex: http://localhost:3000/auth/central/callback>",
      "staging": "<idem em staging, ou null>",
      "prod": "<idem em produção, ou null>"
    },
    "scopes_needed": ["openid", "profile", "email"]
  },
  "existing_central_integration": {
    "already_exists": <true ou false — procure por rotas/arquivos com termos como
      "central", "sso", "oidc", "oauth", "callback" antes de responder false>,
    "location": ["<arquivo:linhas da rota/fluxo de login contra o APP CENTRAL, se existir>"],
    "claims_received_but_unused": ["<claims que o código já recebe do token/userinfo
      (ex: 'permissions', 'roles') mas não usa em lugar nenhum ainda>"],
    "description": "<o que esse login já faz hoje, em 2-3 frases; null se already_exists=false>"
  },
  "permissions": [
    {
      "code": "<string EXATA usada no código para checar essa permissão, ex: 'protocolo.criar'>",
      "name": "<nome curto e legível pra exibir numa tela de admin>",
      "description": "<o que essa permissão libera, em 1 frase>",
      "found_in": ["<arquivo:linha ou rota onde esse check acontece>"]
    }
  ],
  "internal_roles_detected": [
    {
      "role_name": "<se o sistema já tiver conceito próprio de papel/role, ex: 'admin', 'atendente'>",
      "maps_to_permissions": ["<codes da lista acima que esse papel normalmente teria>"],
      "is_real_hierarchy": <true se for um papel fixo com regras próprias; false se
        for só um rótulo genérico (ex: session/perfil de "qualquer usuário logado")
        e o acesso de verdade vier de outro lugar (dict/coluna por usuário)>
    }
  ],
  "storage_model": "<como o acesso por usuário é persistido hoje: 'coluna SQL',
    'tabela separada de permissões', 'campo JSON/dict no documento do usuário',
    'nao ha persistencia, e hardcoded', etc.>",
  "public_routes": ["<rotas que hoje NÃO exigem sessão/login, pra não quebrar nada>"],
  "notes": "<qualquer coisa importante que não coube nos campos acima: login(s)
    atual(is) que serão substituídos, permissões condicionais, ausência de campo
    'ativo/status' pra desativar usuário, ambientes que não existem (ex: sem
    staging), particularidades de arquitetura, etc.>"
}

Regras importantes:
1. NÃO invente permissões que não existem no código. Cada item de "permissions"
   precisa corresponder a uma checagem de autorização REAL (decorator, middleware,
   if de permissão/role, guard de rota, feature flag de acesso) encontrada no
   código-fonte — cite o arquivo E a linha.
2. Se o sistema ainda não tem nenhum controle de permissão implementado, retorne
   "permissions": [] e explique em "notes" quais telas/ações provavelmente vão
   precisar de controle (na sua avaliação como quem conhece o código).
3. "code" deve ser uma string estável em formato "recurso.ação" (ex: "clientes.editar",
   "relatorios.exportar") — se o código já usa outra convenção de nomes, mantenha
   a convenção existente ao invés de inventar uma nova.
4. redirect_uris deve ser a rota exata que vai RECEBER o "code" do OAuth (o
   callback), não a home do sistema.
5. Além de checagens de ACESSO (pode/não pode fazer X), inclua em "permissions"
   também atributos booleanos por usuário que mudam COMPORTAMENTO ou EXIBIÇÃO
   (ex: "aparece numa listagem pública", "oculto de um painel/TV", "pode fazer uma
   ação fora do fluxo normal"), mesmo que não sejam controle de acesso tradicional
   — é sempre um sim/não por operador+app.
6. "existing_central_integration" é OBRIGATÓRIO e tem que ser preciso — é ele que
   decide se o próximo passo é construir login do zero ou só completar o que já
   existe. Procure ativamente antes de marcar "already_exists": false.
7. Se não tiver certeza absoluta de algo, não omita nem invente — declare a
   incerteza dentro de "notes" (ex.: "não achei rota de logout, pode existir sob
   outro nome").

Devolva só o JSON, nada além dele.
"""

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
