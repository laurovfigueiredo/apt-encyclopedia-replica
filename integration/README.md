# Integração Encyclopedia → SOC-OS v2 (Fase A, risco ~zero)

Integra a enciclopédia estática ao SOC-OS **sem alterar nenhum container saudável**:
nada no backend, banco, worker ou Wazuh. Só o frontend passa a servir os
arquivos estáticos em `/encyclopedia/` + 1 item de menu React.

## Como funciona

- A enciclopédia continua 100% estática (HTML + `data/*.json`, sem backend).
- O `docker-compose.encyclopedia.override.yml` monta a pasta da enciclopédia
  **read-only** dentro do nginx do frontend:
  `/home/soar/apt-encyclopedia-replica` → `/usr/share/nginx/html/encyclopedia`.
- O nginx existente já serve arquivos antes do fallback SPA
  (`try_files $uri $uri/ /index.html`), então `/encyclopedia/index.html`,
  `/encyclopedia/actor.html?id=apt29`, `../data/actors.json` funcionam sem
  mudar `nginx.conf` nem o proxy `/api/`.
- A página React `Encyclopedia.tsx` (copiar para
  `soc-os-v2/frontend/src/pages/`) renderiza um iframe same-origin
  (`/encyclopedia/index.html`) + link "abrir em nova aba". Todas as buscas,
  filtros, Threat Model, heatmaps, matriz inline e `actor.html` continuam
  funcionando porque são JS puro + `fetch` relativo + `localStorage`.
- Portas preservadas: 8000 (api), 8080/3000 (frontend), 5555, 11434.
  A 8090 do systemd pode continuar como fallback ou ser desligada depois.

## Aplicação (nesta ordem, com verificação antes de cada passo)

> Não pule a verificação: a soc-os-v2 hoje roda sem erros e o objetivo é
> manter assim. Rollback de cada passo está indicado.

### 0. Saúde atual (obrigatório antes de tudo)

```bash
cd /home/soar/soc-os-v2
docker compose ps
curl -s -o /dev/null -w "api health: %{http_code}\n" http://localhost:8000/health
curl -s -o /dev/null -w "frontend: %{http_code}\n" http://localhost:8080/
git status --short
```

Só prossiga com tudo healthy e `git status` limpo (ou com snapshot feito).

### 1. Validar o override sem aplicar

```bash
cd /home/soar/soc-os-v2
cp /home/soar/apt-encyclopedia-replica/integration/docker-compose.encyclopedia.override.yml ./docker-compose.encyclopedia.override.yml
docker compose -f docker-compose.yml -f docker-compose.encyclopedia.override.yml config | grep -A3 encyclopedia
```

Esperado: volume `../apt-encyclopedia-replica:/usr/share/nginx/html/encyclopedia:ro`
aparecendo no serviço `frontend`. Se o `config` falhar, PARE aqui.

### 2. Subir só o frontend com o volume (backend/banco intactos)

```bash
cd /home/soar/soc-os-v2
docker compose -f docker-compose.yml -f docker-compose.encyclopedia.override.yml up -d frontend
sleep 5
curl -s -o /dev/null -w "encyclopedia: %{http_code}\n" http://localhost:8080/encyclopedia/index.html
curl -s -o /dev/null -w "actor: %{http_code}\n" "http://localhost:8080/encyclopedia/actor.html?id=apt29"
curl -s -o /dev/null -w "data: %{http_code}\n" http://localhost:8080/encyclopedia/data/actors.json
curl -s -o /dev/null -w "api health: %{http_code}\n" http://localhost:8000/health
curl -s -o /dev/null -w "frontend: %{http_code}\n" http://localhost:8080/
```

Esperado: 200 em todas. Rollback: `docker compose up -d frontend` (sem o
`-f override`) volta ao estado anterior.

### 3. Item de menu React (única mudança de código na soc-os-v2)

```bash
cp /home/soar/apt-encyclopedia-replica/integration/Encyclopedia.tsx /home/soar/soc-os-v2/frontend/src/pages/Encyclopedia.tsx
```

Depois, em `soc-os-v2/frontend/src/App.tsx`, adicionar em `NAV`:
`{ to: '/encyclopedia', label: 'Encyclopedia', badge: 'CTI', badgeColor: '#0a84ff' },`
e nas `<Routes>`:
`<Route path="/encyclopedia" element={<Encyclopedia />} />`
(com o `import Encyclopedia from './pages/Encyclopedia'` no topo).
Rebuild só do frontend:
```bash
cd /home/soar/soc-os-v2
docker compose -f docker-compose.yml -f docker-compose.encyclopedia.override.yml build frontend
docker compose -f docker-compose.yml -f docker-compose.encyclopedia.override.yml up -d frontend
```

Verificação: abrir `http://<host>:8080/encyclopedia`, navegar nas 11 páginas,
testar buscas, Threat Model, `actor.html?id=apt29`; confirmar que
`/alerts`, `/mitre`, `/threat-map` e `/api/*` continuam normais.
Rollback: `git checkout -- frontend/src/App.tsx`, remover `Encyclopedia.tsx`,
rebuild + `up -d frontend`.

## Fases seguintes (não incluídas aqui)

- **Fase B**: endpoint FastAPI read-only (`/api/v1/encyclopedia/...`) servindo
  os JSONs + enriquecimento no `ai_module` (triage/IOC intel).
- **Fase C**: ingestão no Postgres + correlação alerta↔ator (migration nova,
  backup `pg_dump` antes, teste em staging).

## Arquivos deste diretório

- `docker-compose.encyclopedia.override.yml` — volume read-only, sem editar o compose original.
- `Encyclopedia.tsx` — página React iframe same-origin para copiar à soc-os-v2.
- `verify.sh` — checagem automatizada do passo 2 (health + 200s).
