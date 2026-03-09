# databases

Infraestrutura interna para busca de credenciais vazadas em bases de dados de stealer logs, utilizada como suporte a engajamentos de pentest e notificação de clientes expostos.

---

## Estrutura

```
databases/
├── server.py          # Servidor HTTP com interface web
├── Dockerfile
├── docker-compose.yml
├── search_cache.db    # Cache SQLite (gerado automaticamente)
├── dbs               # Bases de dados em texto plano
```

---

## Formato dos dados

Os arquivos em `dbs/` seguem o formato padrão de stealer logs:

```
<url>:<usuario>:<senha>
```

Exemplos de origem: logs de infostealer, combo lists públicas.

---

## Servidor

Servidor HTTP em Python puro, sem dependências externas além do `ripgrep` (instalado automaticamente no Docker).

### Iniciar direto

```bash
python3 server.py
```

### Iniciar via Docker

```bash
docker compose up -d
```

**Acesso:** `http://localhost:8081`
**Auth:** definido em `.env` (`USERNAME` / `PASSWORD`)

### Endpoints

| Endpoint | Descrição |
|---|---|
| `GET /` | Interface web |
| `GET /search?q=<termo>&page=<n>` | Busca com `rg` nas bases em `dbs/` |
| `GET /cat?file=<caminho>` | Leitura de arquivo dentro de `dbs/` |
| `GET /health` | Health check |

### Comportamento da busca

- Usa `ripgrep` em paralelo: busca em `passwords.txt` (subdiretórios) e em `*.txt` na raiz de `dbs/`
- Limite de **5.000 matches por arquivo** e **100.000 linhas totais** por busca
- Resultados paginados (5.000 linhas/página) com cache SQLite de 10 dias
- Timeout de 60 segundos por busca

### Exemplo de uso

```bash
# Buscar domínio do cliente
curl -u db:N3tc0nn@2021 "http://localhost:8081/search?q=empresa\.com\.br"

# Página 2 dos resultados
curl -u db:N3tc0nn@2021 "http://localhost:8081/search?q=empresa\.com\.br&page=2"
```

---

## Fluxo de trabalho

1. Extrair arquivos de `zips/` para `dbs/` antes de usar
2. Buscar pelo domínio ou e-mails do cliente via `/search`
3. Navegar pelas páginas de resultado se necessário
4. Consolidar resultados e incluir no relatório de pentest
5. Notificar o cliente com as credenciais encontradas para rotação imediata

---

## Observações

- Os dados são sensíveis — restringir acesso à rede local ou VPN
- Trocar as credenciais padrão do servidor antes de expor em rede
- O endpoint `/cat` é restrito ao diretório `dbs/` (path traversal bloqueado)
- O `search_cache.db` pode crescer — limpar manualmente se necessário
