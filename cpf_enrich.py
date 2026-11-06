#!/usr/bin/env python3
"""language: Python 3.12, file: cpf_enrich.py, target: Linux (companion of server.py), stdlib only

Enriquecimento de CPF via querybuscas.com + grafo de parentes (BFS até `depth` hops)
+ persistência em SQLite (vault_graph.db).

Fluxo de autenticação (re-derivado do app.min.js do próprio querybuscas):
  1. POST /api/auth/login {username, password}          -> Set-Cookie: auth_token
  2. POST /api/consultas/nonce  (Cookie: auth_token)     -> {nonce, sig, expiresAt}
  3. GET  /api/consultas/cpf/<cpf> (Cookie + X-QB-Nonce + X-QB-Sig) -> JSON completo

O par nonce/sig é emitido pelo servidor a cada request (anti-replay); não há HMAC
cliente a replicar — basta pedir um par fresco imediatamente antes de cada consulta.

Custo: cada consulta de CPF consome 1 crédito do plano. Um BFS de profundidade 3
consome até 1 + b + b² + b³ consultas. O cache local em SQLite evita re-consultar
CPFs já importados (use refresh=True para forçar).
"""
import json
import os
import re
import sqlite3
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request


def _load_env(path=".env"):
    """Carrega .env local (sem sobrescrever variáveis já definidas)."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


_load_env()

QB_BASE  = os.environ.get("QUERYBUSCAS_BASE", "https://querybuscas.com")
QB_USER  = os.environ.get("QUERYBUSCAS_USER", "")
QB_PASS  = os.environ.get("QUERYBUSCAS_PASS", "")
DB_PATH  = os.environ.get("GRAPH_DB", "vault_graph.db")

# Capsolver (resolução automática de Turnstile). Vazio = fallback pro widget manual.
CAPSOLVER_API_KEY = os.environ.get("CAPSOLVER_API_KEY", "")
CAPSOLVER_URL     = os.environ.get("CAPSOLVER_API_URL", "https://api.capsolver.com")
CAPSOLVER_TIMEOUT = float(os.environ.get("CAPSOLVER_TIMEOUT", "120"))
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

CPF_ERR = "CPF inválido, inexistente ou proibido"


class CPFError(Exception):
    """CPF inválido/inexistente/proibido — vira mensagem limpa pro usuário."""


CAPTCHA_ERR = "Verificação de segurança necessária (captcha Turnstile)"


class CaptchaError(Exception):
    """A API exige verificação de segurança (Turnstile) na consulta."""

    def __init__(self, sitekey: str = "", action: str = ""):
        super().__init__(CAPTCHA_ERR)
        self.sitekey = sitekey
        self.action = action


def _captcha_payload(status: int, body: str):
    """Retorna (sitekey, action) se a resposta exige Turnstile; senão None."""
    if status != 403:
        return None
    try:
        d = json.loads(body)
        if d.get("requireCaptcha"):
            return d.get("siteKey", ""), d.get("action", "")
    except (json.JSONDecodeError, TypeError):
        pass
    return None


def solve_turnstile(sitekey: str, action: str = "", pageurl: str = QB_BASE) -> str | None:
    """Resolve o Turnstile via Capsolver (AntiTurnstileTaskProxyLess) e retorna o token.

    O Capsolver renderiza o widget num browser remoto com hostname = pageurl, então o
    token sai assinado pro domínio certo SEM precisar mexer em /etc/hosts local.
    Retorna None se a API key não está configurada, a task falhou ou estourou o timeout
    — nesses casos o frontend cai no widget manual.
    """
    if not CAPSOLVER_API_KEY:
        return None
    task: dict = {
        "type": "AntiTurnstileTaskProxyLess",
        "websiteURL": pageurl,
        "websiteKey": sitekey,
    }
    if action:
        task["metadata"] = {"action": action}
    try:
        req = urllib.request.Request(
            CAPSOLVER_URL + "/createTask",
            data=json.dumps({"clientKey": CAPSOLVER_API_KEY, "task": task}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None
    task_id = d.get("taskId")
    if not task_id or d.get("errorId", 0) != 0:
        return None
    deadline = time.time() + CAPSOLVER_TIMEOUT
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                CAPSOLVER_URL + "/getTaskResult",
                data=json.dumps({"clientKey": CAPSOLVER_API_KEY, "taskId": task_id}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return None
        if res.get("errorId", 0):
            return None
        if res.get("status") == "ready":
            return (res.get("solution") or {}).get("token") or None
        if res.get("status") == "failed":
            return None
        time.sleep(3)
    return None


_qb_lock = threading.Lock()   # serializa login/nonce/consulta (cookie único)


class QBClient:
    """Cliente mínimo do querybuscas: login, nonce/sig e consulta de CPF."""

    def __init__(self, user: str = "", password: str = ""):
        self.user = user or QB_USER
        self.password = password or QB_PASS
        self.auth_token = os.environ.get("QUERYBUSCAS_TOKEN", "") or self._token_load()

    def _token_load(self) -> str:
        """Carrega o auth_token persistido (evita login repetido → 429)."""
        try:
            con = sqlite3.connect(DB_PATH)
            con.execute("CREATE TABLE IF NOT EXISTS sessao (chave TEXT PRIMARY KEY, valor TEXT)")
            row = con.execute("SELECT valor FROM sessao WHERE chave='auth_token'").fetchone()
            con.close()
            return row[0] if row else ""
        except Exception:
            return ""

    def _token_save(self, token: str) -> None:
        try:
            con = sqlite3.connect(DB_PATH)
            con.execute("CREATE TABLE IF NOT EXISTS sessao (chave TEXT PRIMARY KEY, valor TEXT)")
            con.execute("INSERT OR REPLACE INTO sessao (chave, valor) VALUES ('auth_token', ?)", (token,))
            con.commit()
            con.close()
        except Exception:
            pass

    # --- plumbing -----------------------------------------------------------
    def _request(self, url, method="GET", data=None, headers=None):
        h = {"User-Agent": UA, "Accept": "*/*",
             "Referer": QB_BASE + "/pages/consultas/Cpf"}
        if headers:
            h.update(headers)
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=h, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers
        with resp:
            return resp.status, resp.read().decode("utf-8", "replace"), resp.headers

    def login(self) -> bool:
        if not self.user or not self.password:
            raise RuntimeError("QUERYBUSCAS_USER/QUERYBUSCAS_PASS ausentes")
        status, body, headers = self._request(
            QB_BASE + "/api/auth/login", "POST",
            {"username": self.user, "password": self.password})
        if status != 200:
            raise RuntimeError(f"login status {status}: {body[:200]}")
        token = None
        for sc in headers.get_all("Set-Cookie") or []:
            m = re.search(r"auth_token=([^;]+)", sc)
            if m:
                token = m.group(1)
        if not token:
            raise RuntimeError("login ok mas sem Set-Cookie auth_token")
        self.auth_token = token
        self._token_save(token)
        return True

    def _authed_headers(self):
        return {"Cookie": f"auth_token={self.auth_token}"}

    def _nonce(self):
        status, body, _ = self._request(
            QB_BASE + "/api/consultas/nonce", "POST", headers=self._authed_headers())
        if status == 401:
            return None   # token expirado — caller re-loga
        if status != 200:
            raise RuntimeError(f"nonce status {status}: {body[:200]}")
        return json.loads(body)

    def consulta(self, cpf: str) -> dict | None:
        """Consulta um CPF. Re-faz login em 401; resolve Turnstile via Capsolver se pedir."""
        solved = False
        for attempt in (1, 2, 3):
            if not self.auth_token:
                self.login()
            nonce = self._nonce()
            if nonce is None:
                if attempt == 1:
                    self.auth_token = ""
                    self.login()
                    continue
                raise RuntimeError("sessão expirada, login falhou")
            headers = self._authed_headers()
            headers["X-QB-Nonce"] = nonce["nonce"]
            headers["X-QB-Sig"] = nonce["sig"]
            status, body, _ = self._request(
                f"{QB_BASE}/api/consultas/cpf/{cpf}", "GET", headers=headers)
            if status == 200:
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return None
            if status == 401 and attempt == 1:
                self.auth_token = ""
                continue
            cap = _captcha_payload(status, body)
            if cap:
                if solved:
                    raise CaptchaError(*cap)
                token = solve_turnstile(cap[0], cap[1])
                if not token:
                    raise CaptchaError(*cap)
                try:
                    humano = self.verificar_humano(token)
                except Exception:
                    humano = False
                if not humano:
                    raise CaptchaError(*cap)
                solved = True
                continue
            if status in (400, 403, 404, 422):
                raise CPFError(CPF_ERR)
            raise RuntimeError(f"consulta {cpf} status {status}: {body[:200]}")
        return None

    def busca_nome(self, nome: str) -> list[dict]:
        """Busca homônimos por nome. Retorna [{cpf, nome, nascimento}].

        Cada chamada consome 1 crédito. Re-faz login em 401; resolve Turnstile via Capsolver.
        """
        solved = False
        for attempt in (1, 2, 3):
            if not self.auth_token:
                self.login()
            nonce = self._nonce()
            if nonce is None:
                if attempt == 1:
                    self.auth_token = ""
                    self.login()
                    continue
                raise RuntimeError("sessão expirada, login falhou")
            headers = self._authed_headers()
            headers["X-QB-Nonce"] = nonce["nonce"]
            headers["X-QB-Sig"] = nonce["sig"]
            status, body, _ = self._request(
                f"{QB_BASE}/api/consultas/nome/{urllib.parse.quote(nome)}",
                "GET", headers=headers)
            if status == 200:
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    return []
                out = []
                for r in data.get("RESULTADOS") or []:
                    cpf = re.sub(r"\D", "", str(r.get("CPF", "")))
                    if cpf:
                        out.append({"cpf": cpf, "nome": r.get("NOME", ""),
                                    "nascimento": r.get("NASCIMENTO", "")})
                return out
            if status == 401 and attempt == 1:
                self.auth_token = ""
                continue
            cap = _captcha_payload(status, body)
            if cap:
                if solved:
                    raise CaptchaError(*cap)
                token = solve_turnstile(cap[0], cap[1])
                if not token:
                    raise CaptchaError(*cap)
                try:
                    humano = self.verificar_humano(token)
                except Exception:
                    humano = False
                if not humano:
                    raise CaptchaError(*cap)
                solved = True
                continue
            if status in (400, 403, 404, 422):
                raise CPFError(CPF_ERR)
            raise RuntimeError(f"busca_nome {nome} status {status}: {body[:200]}")
        return []

    def verificar_humano(self, token: str) -> bool:
        """Valida o token Turnstile e marca a sessão como humana.

        Depois de um 403 requireCaptcha, o frontend resolve o widget e manda o
        token pra cá; o próximo consulta()/busca_nome() deve passar sem captcha.
        """
        status, body, _ = self._request(
            QB_BASE + "/api/consultas/verificar-humano", "POST",
            data={"token": token}, headers=self._authed_headers())
        if status != 200:
            raise RuntimeError(f"verificar-humano status {status}: {body[:200]}")
        try:
            return bool(json.loads(body).get("success"))
        except json.JSONDecodeError:
            return False


# --- normalização -----------------------------------------------------------
def _first(*vals):
    for v in vals:
        if v not in (None, "", "Sem Informação", 0):
            return v
    return ""


def _as_list(x):
    """Normaliza DADOS (list | dict | None) para lista."""
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return [x] if x else []
    return []


def _sem_acento(s):
    return "".join(c for c in unicodedata.normalize("NFD", str(s or ""))
                   if unicodedata.category(c) != "Mn")


def _tipo_label(raw: str) -> str:
    """Traduz TIPO_VINCULO do querybuscas (MAE, IRMA(O), ...) para rótulo curto."""
    t = re.sub(r"\W+", "", _sem_acento(raw).upper())
    mapa = {
        "MAE": "mãe", "PAI": "pai", "IRMAO": "irmã(ão)",
        "FILHO": "filho(a)", "CONJUGE": "cônjuge", "AVO": "avó(ô)",
        "NETO": "neto(a)", "SOBRINHO": "sobrinho(a)", "TIO": "tio(a)",
        "PRIMO": "primo(a)",
    }
    return mapa.get(t, str(raw or "").strip() or "")


def valid_cpf(cpf: str) -> bool:
    """Valida os dígitos verificadores do CPF (11 dígitos, módulo 11)."""
    s = re.sub(r"\D", "", cpf or "")
    if len(s) != 11 or s == s[0] * 11:
        return False
    def dv(base, pesos):
        t = sum(int(d) * p for d, p in zip(base, pesos)) % 11
        return "0" if t < 2 else str(11 - t)
    return (dv(s[:9], range(10, 1, -1)) == s[9]
            and dv(s[:10], range(11, 1, -1)) == s[10])


def normalize(data: dict, cpf: str) -> dict:
    """Achata a resposta COMPLETA do querybuscas em registro estruturado.

    Captura todas as seções, sem descarte: dados pessoais (incluindo origem do
    CPF, título de eleitor, PIS/NIS/CNS, status receita, etc.), empresas,
    e-mails, telefones, bancos, chaves PIX, empregos (com TODOS os períodos),
    vínculos trabalhistas, indicadores de renda, parentes, veículos, endereços,
    interesses, dívida ativa e histórico veicular.
    """
    dp = data.get("DADOS_PESSOAIS") or {}
    parentes = []
    for p in _as_list((data.get("PARENTES") or {}).get("DADOS")):
        c = re.sub(r"\D", "", str(p.get("CPF", "")))
        if c:
            parentes.append({"cpf": c, "nome": p.get("NOME", ""),
                             "tipo": _tipo_label(p.get("TIPO_VINCULO", ""))})
    empregos = []
    for e in _as_list((data.get("EMPREGOS") or {}).get("DADOS")):
        cnpj = re.sub(r"\D", "", str(e.get("CNPJ", "")))
        if not cnpj:
            continue
        # preserva TODAS as chaves brutas (ADMISSAO_1/DEMISSAO_1/ADMISSAO_2/…)
        # e adiciona chaves normalizadas p/ grafo e tabela de empregos
        out = dict(e)
        out["cnpj"] = cnpj
        out["razao_social"] = e.get("RAZAO_SOCIAL", "")
        out["admissao"] = _first(e.get("ADMISSAO"), e.get("ADMISSAO_1"))
        out["demissao"] = _first(e.get("DEMISSAO"), e.get("DEMISSAO_1"))
        empregos.append(out)
    return {
        # ── dados pessoais (completo) ──
        "cpf": cpf,
        "nome": dp.get("NOME", ""),
        "sexo": dp.get("SEXO", ""),
        "nascimento": dp.get("NASCIMENTO", ""),
        "nome_mae": dp.get("NOME_MAE", ""),
        "nome_pai": dp.get("NOME_PAI", ""),
        "municipio": dp.get("MUNICIPIO_NASCIMENTO", ""),
        "raca": dp.get("RACA", ""),
        "tipo_sanguineo": dp.get("TIPO_SANGUINEO", ""),
        "rg": dp.get("RG", ""),
        "origem_cpf": dp.get("ORIGEM_CPF") or {},
        "renda": dp.get("RENDA"),
        "score": dp.get("SCORE", ""),
        "estado_civil": dp.get("ESTADO_CIVIL", ""),
        "obito": dp.get("OBITO", ""),
        "status_receita": dp.get("STATUS_RECEITA", ""),
        "recebe_inss": dp.get("RECEBE_INSS", ""),
        "pis": dp.get("PIS"),
        "nis": dp.get("NIS", ""),
        "cns": dp.get("CNS", ""),
        "titulo_eleitor": dp.get("TITULO_ELEITOR") or {},
        "classe_social": dp.get("CLASSE_SOCIAL", ""),
        "escolaridade": dp.get("ESCOLARIDADE", ""),
        "profissao": dp.get("PROFISSAO", ""),
        # ── seções ──
        "parentes": parentes,
        "empregos": empregos,
        "empresas": _as_list((data.get("EMPRESAS") or {}).get("DADOS")),
        "emails": _as_list((data.get("EMAILS") or {}).get("DADOS")),
        "telefones": _as_list((data.get("TELEFONES") or {}).get("DADOS")),
        "bancos": _as_list((data.get("BANCOS") or {}).get("DADOS")),
        "chaves_pix": _as_list((data.get("CHAVES_PIX") or {}).get("DADOS")),
        "vinculos_trabalhistas": _as_list((data.get("VINCULOS_TRABALHISTAS") or {}).get("DADOS")),
        "indicadores_renda": data.get("INDICADORES_RENDA") or {},
        "veiculos": _as_list((data.get("VEICULOS") or {}).get("DADOS")),
        "enderecos": _as_list((data.get("ENDERECOS") or {}).get("DADOS")),
        "interesses": data.get("INTERESSES_PESSOAIS") or {},
        "divida_ativa": data.get("DIVIDA_ATIVA") or {},
        "historico_veicular": _as_list((data.get("HISTORICO_VEICULAR") or {}).get("DADOS")),
    }


# --- persistência -----------------------------------------------------------
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS pessoas (
            cpf          TEXT PRIMARY KEY,
            nome         TEXT, sexo TEXT, nascimento TEXT,
            nome_mae     TEXT, nome_pai TEXT, municipio TEXT, raca TEXT,
            renda        REAL, score TEXT, obito TEXT,
            escolaridade TEXT, profissao TEXT,
            emails       TEXT, telefones TEXT, enderecos TEXT,
            raw_json     TEXT,
            updated_at   REAL
        );
        CREATE TABLE IF NOT EXISTS parentes (
            origem_cpf TEXT, alvo_cpf TEXT, tipo TEXT, nome TEXT,
            PRIMARY KEY (origem_cpf, alvo_cpf, tipo)
        );
        CREATE TABLE IF NOT EXISTS empregos (
            origem_cpf TEXT, cnpj TEXT, razao_social TEXT,
            admissao TEXT, demissao TEXT,
            PRIMARY KEY (origem_cpf, cnpj, admissao)
        );
        CREATE TABLE IF NOT EXISTS correlacoes (
            origem_cpf TEXT, tipo TEXT, nome TEXT,
            alvo_cpf  TEXT, prob REAL, candidatos TEXT,
            updated_at REAL,
            PRIMARY KEY (origem_cpf, tipo, nome)
        );
        CREATE TABLE IF NOT EXISTS sessao (
            chave TEXT PRIMARY KEY, valor TEXT
        );
    """)
    con.commit()
    con.close()


def load_pessoa(cpf: str) -> dict | None:
    """Reconstrói o registro COMPLETO a partir do raw_json persistido.

    Anexa `updated_at` (epoch) para permitir política de expiração/re-consulta.
    """
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT raw_json, updated_at FROM pessoas WHERE cpf=?", (cpf,)).fetchone()
    con.close()
    if not row or not row[0]:
        return None
    try:
        rec = normalize(json.loads(row[0]), cpf)
    except (json.JSONDecodeError, TypeError):
        return None
    rec["updated_at"] = row[1]
    return rec


def save_pessoa(rec: dict, raw: dict):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT OR REPLACE INTO pessoas "
        "(cpf, nome, sexo, nascimento, nome_mae, nome_pai, municipio, raca, "
        " renda, score, obito, escolaridade, profissao, emails, telefones, enderecos, "
        " raw_json, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rec["cpf"], rec["nome"], rec["sexo"], rec["nascimento"], rec["nome_mae"],
         rec["nome_pai"], rec["municipio"], rec["raca"], rec["renda"], rec["score"],
         rec["obito"], rec["escolaridade"], rec["profissao"],
         json.dumps(rec.get("emails") or [], ensure_ascii=False),
         json.dumps(rec.get("telefones") or [], ensure_ascii=False),
         json.dumps(rec.get("enderecos") or [], ensure_ascii=False),
         json.dumps(raw, ensure_ascii=False), time.time()))
    con.executemany(
        "INSERT OR IGNORE INTO parentes (origem_cpf, alvo_cpf, tipo, nome) VALUES (?,?,?,?)",
        [(rec["cpf"], p["cpf"], p["tipo"], p["nome"]) for p in rec["parentes"]])
    con.executemany(
        "INSERT OR IGNORE INTO empregos (origem_cpf, cnpj, razao_social, admissao, demissao) "
        "VALUES (?,?,?,?,?)",
        [(rec["cpf"], e["cnpj"], e["razao_social"], e["admissao"], e["demissao"])
         for e in rec["empregos"]])
    con.commit()
    con.close()


# --- BFS + montagem do grafo ------------------------------------------------
def _pessoa_node(cpf: str, r: dict) -> dict:
    """Nó de pessoa carregando o registro COMPLETO (todas as seções)."""
    node = dict(r)
    node.update({
        "id": f"cpf:{cpf}",
        "label": r["nome"] or cpf,
        "type": "pessoa",
        "parentes_qtd": len(r.get("parentes", [])),
        "empregos_qtd": len(r.get("empregos", [])),
    })
    return node


# campos pessoais que viram "balões" ligados à pessoa (em vez de ficarem juntos
# do nome na legenda/ficha)
ATTR_FIELDS = [
    ("renda", "RENDA"),
    ("score", "SCORE"),
    ("nascimento", "NASCIMENTO"),
    ("sexo", "SEXO"),
    ("estado_civil", "ESTADO CIVIL"),
    ("escolaridade", "ESCOLARIDADE"),
    ("profissao", "PROFISSÃO"),
    ("classe_social", "CLASSE SOCIAL"),
    ("municipio", "NATURALIDADE"),
    ("obito", "ÓBITO"),
]


def _attr_val(chave: str, val) -> str | None:
    """Formata o valor de um balão; None quando não há o que mostrar."""
    if val is None or val == "":
        return None
    s = str(val).strip()
    if not s:
        return None
    if chave == "renda":
        try:
            s = "R$ " + f"{float(s):,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")
        except (ValueError, TypeError):
            s = "R$ " + s
    elif chave == "obito" and re.search(r"n[ãa]o", s, re.I):
        return None
    return s


def _pessoa_attrs(cpf: str, r: dict) -> tuple[list[dict], list[dict]]:
    """Balões (nós `attr`) + arestas cpf→attr para os dados pessoais de uma pessoa."""
    nodes, edges = [], []
    for chave, rotulo in ATTR_FIELDS:
        val = _attr_val(chave, r.get(chave))
        if val is None:
            continue
        nid = f"attr:{cpf}:{chave}"
        nodes.append({"id": nid, "label": rotulo + "\n" + val, "type": "attr",
                      "chave": chave, "rotulo": rotulo, "valor": val, "cpf": cpf})
        edges.append({"source": f"cpf:{cpf}", "target": nid, "label": ""})
    return nodes, edges


def _palavras(s):
    return [w for w in re.split(r"[^a-z0-9]+", _sem_acento(s).lower()) if w]


def _nome_key(s):
    """Chave canônica de nome: sem acento, minúscula, só letras/dígitos, sem espaço."""
    return "".join(_palavras(s))


STOPWORDS = {"da", "de", "do", "dos", "das", "e", "filho", "filha",
             "jr", "junior", "neto", "neta"}
FAIXA_IDADE = {"mãe": (12, 60), "pai": (12, 75)}


def _ano(nascimento) -> int | None:
    m = re.match(r"(\d{4})", str(nascimento or ""))
    return int(m.group(1)) if m else None


def _idade_ok(cand_nasc, seed_nasc, tipo) -> bool | None:
    """Idade do parente na época do nascimento do filho é plausível?

    True/False; None quando falta data (não filtra).
    """
    ca, sa = _ano(cand_nasc), _ano(seed_nasc)
    if ca is None or sa is None:
        return None
    lo, hi = FAIXA_IDADE.get(tipo, (12, 75))
    return lo <= (sa - ca) <= hi


def _score_barato(c, nome, seed_nasc, seed_nome, tipo):
    """Score só com CPF/NOME/NASCIMENTO da busca por nome (sem consultar)."""
    score, sinais = 0, []
    cn, bn = _nome_key(c["nome"]), _nome_key(nome)
    if bn and cn == bn:
        score += 50; sinais.append("nome_exato")
    elif bn and (bn in cn or cn in bn):
        score += 20; sinais.append("nome_parcial")
    ok = _idade_ok(c["nascimento"], seed_nasc, tipo)
    if ok is True:
        score += 30; sinais.append("idade_ok")
    elif ok is False:
        score -= 100; sinais.append("idade_incompativel")
    if seed_nome and (set(_palavras(seed_nome)) - STOPWORDS) & (set(_palavras(c["nome"])) - STOPWORDS):
        score += 10; sinais.append("sobrenome")
    return score, sinais


def _refinar(client, c, seed_cpf, seed, tipo):
    """Consulta o CPF do candidato (1 crédito) e soma sinais fortes.

    Retorna (score_extra, sinais, rec|None). Se o seed aparece como filho no
    PARENTES do candidato, retorna 1000 → confirmação definitiva.
    """
    try:
        with _qb_lock:
            data = client.consulta(c["cpf"])
    except Exception:
        return 0, ["consulta_falhou"], None
    if not data or not data.get("hasResult"):
        return 0, ["sem_dados"], None
    rec = normalize(data, c["cpf"])
    rec["updated_at"] = time.time()
    save_pessoa(rec, data)
    score, sinais = 0, []
    for p in rec.get("parentes", []):
        if p["cpf"] == seed_cpf:
            return 1000, ["filho_confirmado"], rec
    sexo = re.sub(r"\W+", "", _sem_acento(str(rec.get("sexo", ""))).upper())
    if sexo:
        if (tipo == "mãe" and sexo == "F") or (tipo == "pai" and sexo == "M"):
            score += 30; sinais.append("sexo_ok")
        else:
            score -= 100; sinais.append("sexo_incompativel")
    ok = _idade_ok(rec.get("nascimento"), seed.get("nascimento"), tipo)
    if ok is True:
        score += 20; sinais.append("idade_ok")
    elif ok is False:
        score -= 100; sinais.append("idade_incompativel")
    return score, sinais, rec


def _busca_nome_flex(client, nome):
    """busca_nome com fallback para nome composto não indexado pela API.

    O índice /api/consultas/nome não casa sobrenome composto (ex.: o source grava
    o nome da mãe com o sobrenome inteiro do filho). Quando o nome cheio retorna 0,
    tenta "primeiro nome + cada sobrenome" e mescla os resultados (dedup por CPF).
    Retorna (homonimos, consultas_gastas).
    """
    consultas = 1
    res = client.busca_nome(nome)
    if res:
        return res, consultas
    sig = [t for t in nome.split()
           if _sem_acento(t).lower() not in STOPWORDS and len(t) >= 3]
    if len(sig) < 3:
        return [], consultas
    first = sig[0]
    seen: dict[str, dict] = {}
    for surname in sig[1:4]:   # no máx. 3 sobrenomes — limita crédito
        try:
            for c in client.busca_nome(f"{first} {surname}"):
                cpf = c.get("cpf")
                if cpf:
                    seen.setdefault(cpf, c)
        except Exception:
            pass
        consultas += 1
    return list(seen.values()), consultas


def correlacionar_parente(seed_cpf, tipo, nome, client=None, max_candidates=3):
    """Ranqueia homônimos de `nome` por probabilidade de ser pai/mãe do seed.

    Retorna {"resolvido", "candidatos", "consultas"}. Cada candidato tem
    {cpf, nome, nascimento, prob, sinais}. `consultas` = chamadas pagas gastas
    (1 busca por nome + até max_candidates consultas de refino).
    """
    nome = (nome or "").strip()
    if not nome:
        return {"resolvido": False, "candidatos": [], "consultas": 0}
    init_db()
    seed = load_pessoa(seed_cpf) or {}
    client = client or QBClient()
    homonimos, consultas = _busca_nome_flex(client, nome)
    if not homonimos:
        return {"resolvido": False, "candidatos": [], "consultas": consultas}
    seed_nasc, seed_nome = seed.get("nascimento", ""), seed.get("nome", "")
    scored = []
    for c in homonimos:
        s, sinais = _score_barato(c, nome, seed_nasc, seed_nome, tipo)
        if s > 0:
            scored.append({**c, "score": s, "sinais": sinais})
    scored.sort(key=lambda x: -x["score"])
    if not scored:
        return {"resolvido": False, "candidatos": [], "consultas": consultas}
    # se há match exato, descarta os parciais (evita "MARIA" virar 5000 genéricos)
    if scored[0]["score"] >= 50:
        scored = [c for c in scored if c["score"] >= 50]
    if len(scored) == 1:
        return {"resolvido": True, "consultas": consultas,
                "candidatos": [{**scored[0], "prob": 99.0}]}
    # refina o top N (até 3) consultando o CPF de cada
    top = scored[:max_candidates]
    for c in top:
        extra, sinais2, _ = _refinar(client, c, seed_cpf, seed, tipo)
        c["score"] += extra
        for s in sinais2:
            if s not in c["sinais"]:
                c["sinais"].append(s)
        consultas += 1
    top.sort(key=lambda x: -x["score"])
    confirmados = [c for c in top if "filho_confirmado" in c["sinais"]]
    if confirmados:
        return {"resolvido": True, "consultas": consultas,
                "candidatos": [{**confirmados[0], "prob": 100.0}]}
    positivos = [c for c in top if c["score"] > 0][:max_candidates]
    total = sum(c["score"] for c in positivos)
    for c in positivos:
        c["prob"] = round(100.0 * c["score"] / total, 1) if total else 0.0
    return {"resolvido": bool(positivos), "consultas": consultas,
            "candidatos": positivos}


def save_correlacao(origem_cpf, tipo, nome, resultado):
    con = sqlite3.connect(DB_PATH)
    cands = resultado.get("candidatos") or []
    alvo = cands[0].get("cpf", "") if cands else ""
    prob = cands[0].get("prob", 0.0) if cands else 0.0
    con.execute(
        "INSERT OR REPLACE INTO correlacoes "
        "(origem_cpf, tipo, nome, alvo_cpf, prob, candidatos, updated_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (origem_cpf, tipo, nome, alvo, prob,
         json.dumps(cands, ensure_ascii=False), time.time()))
    con.commit()
    con.close()


def load_correlacao(origem_cpf, tipo, nome):
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT candidatos FROM correlacoes WHERE origem_cpf=? AND tipo=? AND nome=?",
        (origem_cpf, tipo, nome)).fetchone()
    con.close()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None


def _parent_nodes(rec: dict, cpf: str, client=None) -> tuple[list[dict], list[dict], int, list[dict]]:
    """Nós de mãe/pai por NOME (sem CPF em PARENTES), com correlação opcional.

    Retorna (nodes, edges, consultas, confirmados).
    - nodes/edges: nós `type=parente` (folha visual, ambíguo ou sem dados).
    - confirmados: lista [{cpf, nome, tipo}] dos parentes RESOLVIDOS (um único
      candidato) — já consultados e salvos no modo web, viram pessoas no grafo.

    Com `client` (modo web), correlaciona e persiste; sem `client` (modo cache),
    lê a correlação persistida. Dedup por TIPO: se PARENTES já traz o vínculo
    "mãe"/"pai", não cria o nó só-nome.
    """
    nodes, edges, consultas, confirmados = [], [], 0, []
    parent_tipos = {p.get("tipo", "") for p in rec.get("parentes", [])}
    for campo, tipo in (("nome_mae", "mãe"), ("nome_pai", "pai")):
        nome = (rec.get(campo) or "").strip()
        if not nome or tipo in parent_tipos:
            continue
        if client is not None:
            try:
                res = correlacionar_parente(cpf, tipo, nome, client=client)
            except Exception:
                res = None
            if res and res.get("candidatos"):
                consultas += res.get("consultas", 0)
                save_correlacao(cpf, tipo, nome, res)
        else:
            cached = load_correlacao(cpf, tipo, nome)
            res = {"candidatos": cached} if cached else None

        if res and len(res.get("candidatos") or []) == 1:
            # um único candidato → mãe/pai confirmado, vira pessoa completa
            alvo = res["candidatos"][0].get("cpf", "")
            if alvo:
                if client is not None and not load_pessoa(alvo):
                    try:
                        with _qb_lock:
                            data = client.consulta(alvo)
                        if data and data.get("hasResult"):
                            prec = normalize(data, alvo)
                            prec["updated_at"] = time.time()
                            save_pessoa(prec, data)
                            consultas += 1
                    except Exception:
                        pass
                if load_pessoa(alvo):
                    confirmados.append({"cpf": alvo, "nome": nome, "tipo": tipo})
                    continue
            # consulta falhou / sem dados no cache → cai no nó folha

        pid = f"{campo}:{_nome_key(nome)}"
        node = {"id": pid, "label": nome, "type": "parente", "nome": nome, "tipo": tipo}
        edge = {"source": f"cpf:{cpf}", "target": pid, "label": tipo, "nome": nome}
        if res and res.get("candidatos"):
            top = res["candidatos"][0]
            node["cpf"] = top.get("cpf", "")
            node["prob"] = top.get("prob", 0.0)
            node["candidatos"] = res["candidatos"]
            node["resolvido"] = res.get("resolvido", False)
            edge["prob"] = top.get("prob", 0.0)
            edge["alvo_cpf"] = top.get("cpf", "")
        nodes.append(node)
        edges.append(edge)
    return nodes, edges, consultas, confirmados


def _dedupe(edges: list[dict]) -> list[dict]:
    """Remove arestas repetidas (source,target,label) preservando ordem."""
    out, seen = [], set()
    for e in edges:
        k = (e["source"], e["target"], e["label"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


STALE_DAYS = 21.0   # dados com mais de 3 semanas são re-consultados na web


def enrich_graph(seed_cpf: str, depth: int = 3, refresh: bool = False,
                 max_nodes: int = 200, pause: float = 0.4,
                 max_age: float = STALE_DAYS, correlacionar: bool = True,
                 max_correlacoes: int = 4) -> dict:
    """BFS sobre PARENTES a partir do CPF semente, até `depth` hops.

    Cache-first: usa o SQLite se o registro existe e tem menos de `max_age` dias
    (default 21). Registros mais antigos que isso voltam a ser consultados na
    web, como se fosse cache-miss — mesma política do refresh manual.
    """
    depth = max(0, min(int(depth), 4))
    if not valid_cpf(seed_cpf):
        raise CPFError(CPF_ERR)
    init_db()
    client = QBClient()
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(seed_cpf, 0)]
    pessoas: dict[str, dict] = {}
    parente_edges: list[dict] = []
    emp_edges: list[dict] = []
    name_nodes: dict[str, dict] = {}
    name_edges: list[dict] = []
    empresas: dict[str, str] = {}
    consultas = 0
    n_corr = 0

    while queue and len(seen) < max_nodes:
        cpf, d = queue.pop(0)
        if cpf in seen:
            continue
        seen.add(cpf)

        rec = None
        if not refresh:
            rec = load_pessoa(cpf)
            if rec is not None and rec.get("updated_at"):
                if time.time() - rec["updated_at"] > max_age * 86400:
                    rec = None   # expirou: re-consulta a web

        if rec is None:
            try:
                with _qb_lock:
                    data = client.consulta(cpf)
            except CPFError:
                if cpf == seed_cpf:
                    raise
                continue
            except Exception:
                if cpf == seed_cpf:
                    raise
                continue
            consultas += 1
            if not data or not data.get("hasResult"):
                if cpf == seed_cpf:
                    raise CPFError(CPF_ERR)
                continue
            rec = normalize(data, cpf)
            rec["updated_at"] = time.time()
            save_pessoa(rec, data)
            time.sleep(pause)
        pessoas[cpf] = rec

        for e in rec["empregos"]:
            empresas[e["cnpj"]] = e["razao_social"] or e["cnpj"]
            emp_edges.append({"source": f"cpf:{cpf}", "target": f"cnpj:{e['cnpj']}",
                              "label": "emprego", "razao": e["razao_social"]})

        for v in rec.get("vinculos_trabalhistas", []):
            cnpj = re.sub(r"\D", "", str(v.get("CNPJ", "")))
            if not cnpj:
                continue
            razao = v.get("RAZAO_SOCIAL", "")
            empresas[cnpj] = razao or cnpj
            emp_edges.append({"source": f"cpf:{cpf}", "target": f"cnpj:{cnpj}",
                              "label": "emprego", "razao": razao})

        pc = client if (correlacionar and n_corr < max_correlacoes) else None
        nn, ne, used, confirmados = _parent_nodes(rec, cpf, client=pc)
        n_corr += used
        consultas += used
        for n in nn:
            name_nodes[n["id"]] = n
        name_edges += ne

        if d < depth:
            for conf in confirmados:
                parente_edges.append({"source": f"cpf:{cpf}", "target": f"cpf:{conf['cpf']}",
                                      "label": conf["tipo"], "nome": conf["nome"]})
                if conf["cpf"] not in seen:
                    queue.append((conf["cpf"], d + 1))
            for p in rec["parentes"]:
                parente_edges.append({"source": f"cpf:{cpf}", "target": f"cpf:{p['cpf']}",
                                      "label": p["tipo"], "nome": p["nome"]})
                if p["cpf"] not in seen:
                    queue.append((p["cpf"], d + 1))

    # dedupe de arestas preservando ordem
    nodes = [_pessoa_node(cpf, r) for cpf, r in pessoas.items()]
    nodes += [{"id": f"cnpj:{cnpj}", "label": razao, "type": "empresa", "cnpj": cnpj}
              for cnpj, razao in empresas.items()]
    nodes += list(name_nodes.values())

    # balões de dados pessoais (score, renda, nascimento, …) ligados a cada pessoa
    attr_nodes, attr_edges = [], []
    for cpf, r in pessoas.items():
        an, ae = _pessoa_attrs(cpf, r)
        attr_nodes += an
        attr_edges += ae
    nodes += attr_nodes

    # remove arestas de parente cujo alvo não virou nó (consulta falhou / sem dados)
    valid_cpfs = set(pessoas.keys())
    parente_edges = [e for e in parente_edges if e["target"].split(":", 1)[-1] in valid_cpfs]

    return {
        "seed": seed_cpf,
        "depth": depth,
        "consultas": consultas,
        "nodes": nodes,
        "edges": (_dedupe(parente_edges) + _dedupe(emp_edges)
                  + _dedupe(name_edges) + _dedupe(attr_edges)),
    }


def stored_graph(seed_cpf: str, depth: int = 3) -> dict:
    """Reconstrói o grafo direto do SQLite, sem tocar a API (consome 0 créditos)."""
    init_db()
    con = sqlite3.connect(DB_PATH)
    seen, queue = set(), [(seed_cpf, 0)]
    pessoas, parente_edges, emp_edges, empresas = {}, [], [], {}
    name_nodes, name_edges = {}, []
    while queue:
        cpf, d = queue.pop(0)
        if cpf in seen:
            continue
        seen.add(cpf)
        rec = load_pessoa(cpf)
        if not rec:
            continue
        pessoas[cpf] = rec
        for e in rec["empregos"]:
            empresas[e["cnpj"]] = e["razao_social"] or e["cnpj"]
            emp_edges.append({"source": f"cpf:{cpf}", "target": f"cnpj:{e['cnpj']}",
                              "label": "emprego"})
        for v in rec.get("vinculos_trabalhistas", []):
            cnpj = re.sub(r"\D", "", str(v.get("CNPJ", "")))
            if not cnpj:
                continue
            razao = v.get("RAZAO_SOCIAL", "")
            empresas[cnpj] = razao or cnpj
            emp_edges.append({"source": f"cpf:{cpf}", "target": f"cnpj:{cnpj}",
                              "label": "emprego"})
        nn, ne, _, confirmados = _parent_nodes(rec, cpf, client=None)
        for n in nn:
            name_nodes[n["id"]] = n
        name_edges += ne
        if d < depth:
            for conf in confirmados:
                parente_edges.append({"source": f"cpf:{cpf}", "target": f"cpf:{conf['cpf']}",
                                      "label": conf["tipo"], "nome": conf["nome"]})
                if conf["cpf"] not in seen:
                    queue.append((conf["cpf"], d + 1))
            for p in rec["parentes"]:
                parente_edges.append({"source": f"cpf:{cpf}", "target": f"cpf:{p['cpf']}",
                                      "label": p["tipo"], "nome": p["nome"]})
                if p["cpf"] not in seen:
                    queue.append((p["cpf"], d + 1))
    con.close()

    nodes = [_pessoa_node(cpf, r) for cpf, r in pessoas.items()]
    nodes += [{"id": f"cnpj:{cnpj}", "label": razao, "type": "empresa", "cnpj": cnpj}
              for cnpj, razao in empresas.items()]
    nodes += list(name_nodes.values())
    attr_nodes, attr_edges = [], []
    for cpf, r in pessoas.items():
        an, ae = _pessoa_attrs(cpf, r)
        attr_nodes += an
        attr_edges += ae
    nodes += attr_nodes
    valid_cpfs = set(pessoas.keys())
    parente_edges = [e for e in parente_edges if e["target"].split(":", 1)[-1] in valid_cpfs]
    return {"seed": seed_cpf, "depth": depth, "consultas": 0,
            "nodes": nodes,
            "edges": (_dedupe(parente_edges) + _dedupe(emp_edges)
                      + _dedupe(name_edges) + _dedupe(attr_edges))}


if __name__ == "__main__":
    import sys
    cpf = re.sub(r"\D", "", sys.argv[1] if len(sys.argv) > 1 else "")
    if not cpf:
        print("uso: python cpf_enrich.py <cpf> [depth]")
        sys.exit(1)
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    g = enrich_graph(cpf, depth=depth)
    print(json.dumps(g, ensure_ascii=False, indent=2))
