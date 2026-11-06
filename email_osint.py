#!/usr/bin/env python3
"""language: Python 3.12, file: email_osint.py, target: Linux (companion of server.py)

OSINT de e-mail em quatro frentes:

  1. holehe           — enumera em quais sites o e-mail tem conta (megadose/holehe v1.61).
  2. emailosint.org   — validador de contas + data breaches + stealer logs (stream SSE).
  3. user-scanner     — ~220 sites (creator/adult/dating/crm/jobs/dev/...) com browser
                        impersonation via curl_cffi (TLS fingerprint) pra atravessar
                        bot-walls que o holehe (httpx puro) não passa. Vendado em
                        user_scanner/ (só o subconjunto de email; user_scan fora).
  4. AWS API Gateway  — rotação de IP por request, port fiel do IPRotate.py (PortSwigger).

Fluxo do emailosint.org (re-derivado do bundle React do próprio site):
  POST https://api.emailosint.org/lookup/email-stream
    headers: Content-Type: application/json, Accept: text/event-stream,
             x-captcha-token: <token Turnstile>   (obrigatório p/ uso anônimo)
    body:   {"email": "..."}
  Resposta: Server-Sent Events (SSE), eventos:
    init / validator_result / identifier_result / data_breaches /
    stealer_logs / ai_summary / progress / done / error / history_saved.

  sitekey Turnstile: 0x4AAAAAADFWVaOUWO9IqmDd, action: demo_lookup.
  O token é resolvido via Capsolver (reusa cpf_enrich.solve_turnstile), então nada
  de /etc/hosts — websiteURL = https://emailosint.org (domínio autorizado do sitekey).

Rotação de IP (port do IPRotate.py):
  - Cria uma API Gateway REST (REGIONAL) por região com resource `{proxy+}`, método
    ANY e integração HTTP_PROXY apontando pra `{protocol}://{host}/{proxy}`.
  - Cada API criada ganha um edge node novo → IP de saída novo. O IPRotate.py original
    cria N APIs (uma por região) e faz round-robin; o modo one-shot daqui cria/destrói
    uma API por request, que é a rotação real "a cada request".
  - Limitação estrutural: a integração HTTP_PROXY aponta pra UM host por API. Funciona
    direto pro emailosint.org (host único); pro holehe (fan-out de ~130 hosts) não se
    aplica — cada host exigiria uma API própria, o que é inviável por custo/latência.
"""
import json
import os
import re
import sqlite3
import time
import uuid
from urllib.parse import urlparse

import httpx

# Reusa env + Capsolver do módulo CPF (carrega .env no import).
import cpf_enrich  # noqa: F401  (loads .env e expõe solve_turnstile)

EMAIL_RE = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

# ── emailosint.org ──────────────────────────────────────────────────────────
EMAILOSINT_BASE     = os.environ.get("EMAILOSINT_BASE", "https://api.emailosint.org")
EMAILOSINT_PAGEURL  = os.environ.get("EMAILOSINT_PAGEURL", "https://emailosint.org")
EMAILOSINT_SITEKEY  = os.environ.get("EMAILOSINT_SITEKEY", "0x4AAAAAADFWVaOUWO9IqmDd")
EMAILOSINT_ACTION   = os.environ.get("EMAILOSINT_ACTION", "demo_lookup")

# ── AWS / rotação de IP ─────────────────────────────────────────────────────
AWS_ACCESS      = os.environ.get("AWS_ACCESS", "")
AWS_SECRET      = os.environ.get("AWS_SECRET", "")
AWS_SESSION     = os.environ.get("AWS_SESSION_TOKEN", "")
AWS_REGION      = os.environ.get("AWS_REGION", "") or "us-east-1"
AWS_REGIONS     = [r.strip() for r in os.environ.get(
                    "AWS_REGIONS",
                    "us-east-1,us-west-1,us-east-2,us-west-2,"
                    "eu-central-1,eu-west-1,eu-west-2,eu-west-3,"
                    "sa-east-1,eu-north-1").split(",") if r.strip()]
GATEWAY_STAGE   = os.environ.get("GATEWAY_STAGE", "iprotate")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

# ── user-scanner (vendado em user_scanner/) ────────────────────────────────
# Concorrência/tempo do sweep (padrões = os do email_orchestrator do projeto).
# allow_loud=False pula os módulos que avisam o alvo via forgot-password; no_nsfw
# descarta a categoria adult. Nada aqui toca o httpx global: a rota de email do
# user-scanner é acionada com runner próprio, sem importar email_orchestrator
# (que monkey-patcha httpx.Client/AsyncClient no import).
US_CONCURRENCY = int(os.environ.get("US_CONCURRENCY", "25"))
US_NO_NSFW     = os.environ.get("US_NO_NSFW", "0") in ("1", "true", "yes")
US_ALLOW_LOUD  = os.environ.get("US_ALLOW_LOUD", "0") in ("1", "true", "yes")
US_TIMEOUT     = float(os.environ.get("US_TIMEOUT", "25"))

# ── holehe ──────────────────────────────────────────────────────────────────
# Fan-out de ~130 módulos. Sem semáforo o trio dispara tudo de uma vez (rajada),
# o que maximiza rateLimit nos serviços. Limitamos a concorrência pra suavizar o
# burst — não elimina os rateLimit de serviços com proteção anti-enumeração
# (google, github, instagram, snapchat...), que o holehe SEMPRE marca rateLimit.
HH_CONCURRENCY = int(os.environ.get("HH_CONCURRENCY", "15"))

# ── cache ───────────────────────────────────────────────────────────────────
EMAIL_DB = os.environ.get("EMAIL_DB", "email_cache.db")


class EmailOSINTError(Exception):
    """Erro estruturado do emailosint.org (captcha, rate limit, etc.)."""

    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


def is_email(email: str) -> bool:
    return bool(re.fullmatch(EMAIL_RE, (email or "").strip()))


# ── AWS API Gateway — rotação de IP (port do IPRotate.py) ──────────────────
def _apigw_client(region):
    import boto3
    kw = {"region_name": region}
    if AWS_ACCESS and AWS_SECRET:
        kw["aws_access_key_id"] = AWS_ACCESS
        kw["aws_secret_access_key"] = AWS_SECRET
        if AWS_SESSION:
            kw["aws_session_token"] = AWS_SESSION
    return boto3.client("apigateway", **kw)


def _build_gateway(host: str, protocol: str = "https", region: str = AWS_REGION,
                   stage: str = GATEWAY_STAGE, xff: str = "") -> str:
    """Cria uma API Gateway REST (REGIONAL) apontando pra `host` e devolve o endpoint.

    Fiel ao IPRotate.py: resource raiz + `{proxy+}`, método ANY, integração HTTP_PROXY.
    Se `xff` é passado, injeta o mapping X-My-X-Forwarded-For → X-Forwarded-For no backend.
    """
    client = _apigw_client(region)
    name = f"iprotate-{uuid.uuid4().hex[:12]}"

    api = client.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]})
    api_id = api["id"]

    root_id = client.get_resources(restApiId=api_id)["items"][0]["id"]

    # resource `{proxy+}` para capturar qualquer path
    proxy_id = client.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="{proxy+}")["id"]

    req_params = {"method.request.path.proxy": True}
    int_params = {"integration.request.path.proxy": "method.request.path.proxy"}
    if xff:
        req_params["method.request.header.X-My-X-Forwarded-For"] = True
        int_params["integration.request.header.X-Forwarded-For"] = \
            "method.request.header.X-My-X-Forwarded-For"

    # raiz → host/
    client.put_method(restApiId=api_id, resourceId=root_id, httpMethod="ANY",
                      authorizationType="NONE", requestParameters=req_params)
    client.put_integration(restApiId=api_id, resourceId=root_id, httpMethod="ANY",
                           type="HTTP_PROXY", integrationHttpMethod="ANY",
                           uri=f"{protocol}://{host}/", requestParameters=int_params)

    # {proxy+} → host/{proxy}
    client.put_method(restApiId=api_id, resourceId=proxy_id, httpMethod="ANY",
                      authorizationType="NONE", requestParameters=req_params)
    client.put_integration(restApiId=api_id, resourceId=proxy_id, httpMethod="ANY",
                           type="HTTP_PROXY", integrationHttpMethod="ANY",
                           uri=f"{protocol}://{host}/{{proxy}}", requestParameters=int_params)

    client.create_deployment(restApiId=api_id, stageName=stage)

    return f"{api_id}.execute-api.{region}.amazonaws.com"


class RotatingGateway:
    """Round-robin por região, exatamente como o IPRotate.py original.

    Cria uma API por região (cada uma com IP de saída próprio) e alterna entre elas
    a cada request. Usar com um único host alvo (ex.: api.emailosint.org).
    """

    def __init__(self, host: str, protocol: str = "https", regions: list | None = None,
                 stage: str = GATEWAY_STAGE, xff: str = ""):
        if not AWS_ACCESS or not AWS_SECRET:
            raise RuntimeError("AWS_ACCESS/AWS_SECRET ausentes no .env")
        self.host = host
        self.protocol = protocol
        self.regions = regions or AWS_REGIONS
        self.stage = stage
        self.xff = xff
        self.endpoints: list[str] = []
        self.api_ids: list[str] = []   # (region, api_id) para destroy
        self._i = 0

    def start(self) -> "RotatingGateway":
        for region in self.regions:
            ep = _build_gateway(self.host, self.protocol, region, self.stage, self.xff)
            self.endpoints.append(ep)
            self.api_ids.append((region, ep.split(".")[0]))
        return self

    def _next(self) -> str:
        ep = self.endpoints[self._i % len(self.endpoints)]
        self._i += 1
        return ep

    def url(self, path_query: str) -> str:
        return f"https://{self._next()}/{self.stage}/{path_query.lstrip('/')}"

    def destroy(self) -> None:
        for region, api_id in self.api_ids:
            try:
                _apigw_client(region).delete_rest_api(restApiId=api_id)
            except Exception:
                pass
        self.endpoints, self.api_ids = [], []

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.destroy()


def request_rotating(host: str, path_query: str, method: str = "GET",
                     headers: dict | None = None, body: bytes | None = None,
                     protocol: str = "https", region: str = AWS_REGION,
                     stage: str = GATEWAY_STAGE, xff: str = "",
                     timeout: float = 60.0):
    """One-shot: cria uma API, envia UM request e destrói → IP novo a cada chamada.

    Retorna (status, texto, headers). Para stream (SSE), use emailosint_lookup,
    que faz o mesmo ciclo com o corpo aberto.
    """
    endpoint = _build_gateway(host, protocol, region, stage, xff)
    time.sleep(1.0)   # deixa a propagação do deploy assentar antes do primeiro hit
    url = f"https://{endpoint}/{stage}/{path_query.lstrip('/')}"
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    if xff:
        h["X-My-X-Forwarded-For"] = xff
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.request(method, url, headers=h, content=body)
            return resp.status_code, resp.text, dict(resp.headers)
    finally:
        try:
            _apigw_client(region).delete_rest_api(restApiId=endpoint.split(".")[0])
        except Exception:
            pass


# ── holehe ─────────────────────────────────────────────────────────────────
def holehe_scan(email: str, timeout: float = 8.0, only_used: bool = False) -> list[dict]:
    """Enumera as contas do e-mail nos ~130 sites. Retorna a lista bruta do holehe.

    Roda `trio.run` num thread dedicado (o handler HTTP já é um thread, então pode
    chamar trio.run direto sem conflito de event loop).
    """
    import trio
    from holehe import core

    async def _run():
        modules = core.import_submodules("holehe.modules")
        websites = core.get_functions(modules)
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        sem = trio.Semaphore(HH_CONCURRENCY)
        out: list[dict] = []
        async def _guarded(w):
            async with sem:
                await core.launch_module(w, email, client, out)
        try:
            async with trio.open_nursery() as nursery:
                for w in websites:
                    nursery.start_soon(_guarded, w)
        finally:
            await client.aclose()
        out = sorted(out, key=lambda i: i.get("name", ""))
        if only_used:
            out = [r for r in out if r.get("exists")]
        return out

    return trio.run(_run)


def summarize_holehe(results: list[dict]) -> dict:
    found = []
    rate_limited = []
    errors = []
    not_found = 0
    for r in results or []:
        if r.get("rateLimit"):
            rate_limited.append(r.get("name") or r.get("domain", ""))
        elif r.get("error"):
            errors.append(r.get("name") or r.get("domain", ""))
        elif r.get("exists") is True:
            found.append({
                "name": r.get("name", ""),
                "domain": r.get("domain", ""),
                "emailrecovery": r.get("emailrecovery"),
                "phoneNumber": r.get("phoneNumber"),
                "others": r.get("others"),
            })
        else:
            not_found += 1
    return {
        "found": found,
        "rate_limited": rate_limited,
        "errors": errors,
        "not_found": not_found,
        "total": len(results or []),
    }


# ── user-scanner ───────────────────────────────────────────────────────────
def summarize_userscanner(results) -> dict:
    """Achata List[Result] do user-scanner num resumo no molde do holehe.

    found = contas registradas (TAKEN); not_found = contagem de sites sem conta
    (AVAILABLE, que são muitos — não listamos um por um); errors/skipped = listas
    de dicts (site_name/url/extra). Cada `found` é o `to_dict()` do Result:
    site_name, category, url, extra (metadados por site) e media.
    """
    from user_scanner.core.result import Status

    found, errors, skipped = [], [], []
    not_found = 0
    for r in results or []:
        if r.status == Status.TAKEN:
            found.append(r.to_dict())
        elif r.status == Status.AVAILABLE:
            not_found += 1
        elif r.status == Status.SKIPPED:
            skipped.append(r.to_dict())
        else:
            errors.append(r.to_dict())
    return {"found": found, "not_found": not_found, "errors": errors,
            "skipped": skipped, "total": len(results or [])}


def userscanner_scan(email: str, concurrency: int = US_CONCURRENCY,
                     no_nsfw: bool = US_NO_NSFW, allow_loud: bool = US_ALLOW_LOUD,
                     timeout: float = US_TIMEOUT,
                     categories: list[str] | None = None) -> dict:
    """Enumera contas do e-mail nos ~220 sites do user-scanner (vended).

    Runner próprio: carrega os módulos via helpers e dispara as `validate_*` num
    pool asyncio com semáforo, espelhando `_async_worker` do email_orchestrator
    mas SEM a parte de console (Progress/Result.show) e SEM importar o módulo que
    monkey-patcha httpx. Assim o httpx do holehe/emailosint segue intocado.

    `categories`: lista opcional de pastas (ex.: ["creator", "social"]); vazio =
    todas as categorias.
    """
    from user_scanner.core.helpers import (
        load_categories, load_modules, get_scan_func, find_category,
        get_site_name, is_loud)
    from user_scanner.core.result import Result
    from user_scanner.core import limits

    import asyncio
    import concurrent.futures
    import inspect

    concurrency = limits.check_concurrency(concurrency)

    all_cats = load_categories(True, no_nsfw)          # {pasta: Path}
    if categories:
        wanted = {c.strip().lower() for c in categories if c and c.strip()}
        cat_map = {k: v for k, v in all_cats.items() if k in wanted}
    else:
        cat_map = all_cats

    modules: list = []
    for path in cat_map.values():
        modules.extend(load_modules(path))

    sem = asyncio.Semaphore(concurrency)

    async def worker(module):
        async with sem:
            site_name = get_site_name(module)
            base = {"site_name": site_name.capitalize(), "username": email,
                    "category": find_category(module) or "Email", "is_email": True}
            func = get_scan_func(module)
            if func is None:
                return Result.error(f"{site_name} has no validate_ function", **base)
            if not allow_loud and is_loud(site_name, is_email=True):
                return Result.skipped(**base)
            kwargs = {}
            if "allow_loud" in inspect.signature(func).parameters:
                kwargs["allow_loud"] = allow_loud
            try:
                if inspect.iscoroutinefunction(func):
                    r = await asyncio.wait_for(func(email, **kwargs), timeout=timeout)
                else:
                    r = await asyncio.wait_for(
                        asyncio.to_thread(func, email, **kwargs), timeout=timeout)
            except asyncio.TimeoutError:
                r = Result.error(f"timeout after {timeout:g}s")
            except Exception as e:  # noqa: BLE001 — Result captura o traceback na reason
                r = Result.error(e)
            return r.update(**base)

    async def run():
        asyncio.get_running_loop().set_default_executor(
            concurrent.futures.ThreadPoolExecutor(max_workers=max(64, concurrency * 2)))
        return await asyncio.gather(*(worker(m) for m in modules))

    return summarize_userscanner(asyncio.run(run()))


# ── emailosint.org ─────────────────────────────────────────────────────────
def _iter_sse(resp) -> "generator[tuple[str, dict], None, None]":
    event, data = "", []
    for line in resp.iter_lines():
        if line == "":
            if event and data:
                try:
                    yield event, json.loads("\n".join(data))
                except json.JSONDecodeError:
                    yield event, {"raw": "\n".join(data)}
            event, data = "", []
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].strip())
    if event and data:
        try:
            yield event, json.loads("\n".join(data))
        except json.JSONDecodeError:
            yield event, {"raw": "\n".join(data)}


def _empty_emailosint():
    return {
        "meta": {},
        "validator": {"registered": [], "unregistered": []},
        "identifier": [],
        "data_breaches": None,
        "stealer_logs": None,
        "ai": None,
        "progress": None,
    }


def emailosint_lookup(email: str, token: str = "", rotate: bool = True,
                      timeout: float = 60.0, xff: str = "") -> dict:
    """Consulta o emailosint.org (SSE) e devolve o relatório estruturado.

    Se `token` está vazio, resolve o Turnstile via Capsolver e tenta de novo.
    Se `rotate` e as credenciais AWS estão presentes, roteia a request por uma
    API Gateway descartável (IP novo).
    """
    if not is_email(email):
        raise EmailOSINTError("e-mail inválido")

    path = "lookup/email-stream"
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    body = json.dumps({"email": email}).encode()

    use_rotate = rotate and bool(AWS_ACCESS and AWS_SECRET)
    host = urlparse(EMAILOSINT_BASE).netloc or "api.emailosint.org"

    def _open_stream(token: str = ""):
        endpoint = None
        if use_rotate:
            try:
                endpoint = _build_gateway(host, "https", AWS_REGION, GATEWAY_STAGE, xff)
                time.sleep(1.0)   # propagação do deploy
            except Exception:
                endpoint = None   # fallback silencioso pra request direta
        if endpoint:
            url = f"https://{endpoint}/{GATEWAY_STAGE}/{path}"
            h = {"User-Agent": UA, **headers}
            if xff:
                h["X-My-X-Forwarded-For"] = xff
        else:
            url = EMAILOSINT_BASE + "/" + path
            h = {**headers, "User-Agent": UA}
        if token:
            h["x-captcha-token"] = token
        client = httpx.Client(timeout=timeout, follow_redirects=False)
        try:
            return client, client.send(
                client.build_request("POST", url, headers=h, content=body),
                stream=True), endpoint
        except Exception:
            client.close()
            raise

    def _destroy(endpoint):
        if endpoint:
            try:
                _apigw_client(AWS_REGION).delete_rest_api(
                    restApiId=endpoint.split(".")[0])
            except Exception:
                pass

    def _run(token: str):
        client, resp, endpoint = _open_stream(token)
        try:
            if resp.status_code != 200:
                # iter_bytes() aplica a decodificação de conteúdo (gzip/deflate/br);
                # iter_raw()/read() devolveriam os bytes comprimidos crus (era o bug
                # do lixo binário), e resp.text em stream=True levanta ResponseNotRead.
                raw = b"".join(resp.iter_bytes()).decode("utf-8", "replace")
                raise EmailOSINTError(_extract_msg(raw, resp.status_code),
                                      _extract_code(raw))
            out = _empty_emailosint()
            for event, payload in _iter_sse(resp):
                if event == "init":
                    out["meta"].update(payload or {})
                elif event == "validator_result":
                    target = ("registered" if payload.get("registered")
                              else "unregistered")
                    out["validator"][target].append(payload.get("module", payload))
                elif event == "identifier_result":
                    out["identifier"].append(payload)
                elif event == "data_breaches":
                    out["data_breaches"] = payload
                elif event == "stealer_logs":
                    out["stealer_logs"] = payload
                elif event == "ai_summary":
                    out["ai"] = payload
                elif event == "progress":
                    out["progress"] = payload
                elif event == "done":
                    out["meta"].update(payload.get("meta") or {})
                    if payload.get("validator"):
                        out["validator"] = payload["validator"]
                    out["progress"] = payload.get("progress", out["progress"])
                elif event == "error":
                    raise EmailOSINTError(
                        str(payload.get("message") or payload.get("error") or "lookup failed"),
                        str(payload.get("error") or payload.get("code") or ""))
            return out
        finally:
            try:
                resp.close()
            except Exception:
                pass
            client.close()
            _destroy(endpoint)

    try:
        return _run(token)
    except EmailOSINTError as e:
        # captcha necessário e ainda não resolvemos → resolve e tenta de novo
        if e.code == "captcha_required" and not token:
            token = cpf_enrich.solve_turnstile(
                EMAILOSINT_SITEKEY, EMAILOSINT_ACTION, EMAILOSINT_PAGEURL)
            if token:
                return _run(token)
        raise


def _extract_msg(raw: str, status: int) -> str:
    try:
        d = json.loads(raw)
        return d.get("message") or d.get("error") or f"HTTP {status}"
    except json.JSONDecodeError:
        if raw.strip():
            return f"HTTP {status}: {raw.strip()[:200]}"
        return f"HTTP {status}"


def _extract_code(raw: str) -> str:
    try:
        d = json.loads(raw)
        return str(d.get("error") or d.get("code") or "")
    except json.JSONDecodeError:
        return ""


# ── cache ───────────────────────────────────────────────────────────────────
def init_email_cache():
    con = sqlite3.connect(EMAIL_DB)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS email_lookups (
            email      TEXT PRIMARY KEY,
            payload    TEXT,
            created_at REAL
        )
    """)
    con.commit()
    con.close()


def get_email_cache(email: str) -> dict | None:
    con = sqlite3.connect(EMAIL_DB)
    row = con.execute(
        "SELECT payload, created_at FROM email_lookups WHERE email=?", (email,)).fetchone()
    con.close()
    if not row:
        return None
    try:
        out = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None
    # persiste indefinidamente (mesma ideia do CPF: load_pessoa/stored_graph —
    # registro não expira sozinho; `refresh=1` força re-scan). `updated_at` exposto
    # pro frontend mostrar a idade do dado.
    out["updated_at"] = row[1]
    return out


def set_email_cache(email: str, payload: dict):
    con = sqlite3.connect(EMAIL_DB)
    con.execute(
        "INSERT OR REPLACE INTO email_lookups (email, payload, created_at) VALUES (?,?,?)",
        (email, json.dumps(payload, ensure_ascii=False), time.time()))
    con.commit()
    con.close()


# ── grafo de investigação ───────────────────────────────────────────────────
def build_email_graph(email: str, holehe=None, emailosint=None,
                      userscanner=None) -> dict:
    """Converte o resultado num grafo cytoscape.

    email (seed) → contas (com foto/nome quando o emailosint acha em rede social)
                 → breaches (timeline) / stealer. Mesma ideia do grafo de CPF.
    """
    nodes_by_id: dict = {}
    edges_by_id: set = set()
    edges: list = []

    def add_node(nid: str, label: str, ntype: str, **extra):
        if nid in nodes_by_id:
            old = nodes_by_id[nid]
            # enriquece o nó existente se a nova fonte traz mais (foto/nome/bio)
            for k, v in extra.items():
                if v and not old.get(k):
                    old[k] = v
            return
        n = {"id": nid, "label": label, "type": ntype}
        n.update(extra)
        nodes_by_id[nid] = n

    def add_edge(source: str, target: str, label: str):
        key = (source, target, label)
        if key in edges_by_id:
            return
        edges_by_id.add(key)
        edges.append({"id": source + "→" + target + ":" + label,
                      "source": source, "target": target, "label": label})

    def _first_str(v):
        """Achata um valor de field (str | lista | dict) na primeira string útil."""
        if isinstance(v, str):
            return v
        if isinstance(v, (list, tuple)):
            for x in v:
                s = _first_str(x)
                if s:
                    return s
            return ""
        if isinstance(v, dict):
            for key in ("value", "url", "text", "formatted"):
                if isinstance(v.get(key), str) and v.get(key):
                    return v[key]
            return ""
        return "" if v is None else str(v)

    # ── emailosint: contas identificadas (com avatar_url = foto da pessoa) ──
    eo = emailosint or {}
    if eo.get("ok") is not False:
        for item in (eo.get("identifier") or []):
            if not isinstance(item, dict):
                continue
            mod = item.get("module") or {}
            name = mod.get("name_formatted") or mod.get("name") or mod.get("domain") or "?"
            domain = mod.get("domain") or ""
            icon = mod.get("icon") or ""
            nid = "conta:" + (mod.get("name") or mod.get("domain") or "?").lower()
            # extrai identidade dos fields do account: foto, nome, username, bio,
            # link, localização, telefone. guarda os fields crus p/ a ficha.
            extra = {"domain": domain, "icon": icon}
            data = item.get("data") or {}
            raw_fields = []
            fn_first = fn_last = ""
            for f in (data.get("fields") or []):
                if not isinstance(f, dict):
                    continue
                k = str(f.get("summary_key") or f.get("key") or "").lower()
                v = f.get("value")
                raw_fields.append({"k": k, "v": v,
                                   "label": f.get("label") or k,
                                   "type": f.get("type") or "string"})
                if v is None or v == "":
                    continue
                if k in ("avatar_url", "profile_image", "avatar") or f.get("type") == "image":
                    extra["avatar"] = _first_str(v)
                elif k == "full_name":
                    extra["full_name"] = _first_str(v)
                elif k == "first_name":
                    fn_first = _first_str(v)
                elif k == "last_name":
                    fn_last = _first_str(v)
                elif k in ("username", "twitter_username", "unique_name", "display_name"):
                    extra.setdefault("username", _first_str(v))
                elif k == "nickname" and not extra.get("username"):
                    extra["username"] = _first_str(v)
                elif k == "bio":
                    extra["bio"] = _first_str(v)
                elif k == "profile_url":
                    extra["profile_url"] = _first_str(v)
                elif k == "links":
                    extra.setdefault("profile_url", _first_str(v))
                elif k in ("location", "locations"):
                    extra["location"] = _first_str(v)
                elif k in ("phone_number", "phone"):
                    extra["phone"] = _first_str(v)
            if not extra.get("full_name") and (fn_first or fn_last):
                extra["full_name"] = (fn_first + " " + fn_last).strip()
            if raw_fields:
                extra["fields"] = raw_fields
            add_node(nid, name, "conta", **extra)
            add_edge("email", nid, "conta")

        # validator.registered — complemento (site marcado como registrado, sem foto)
        for acc in (eo.get("validator") or {}).get("registered") or []:
            if not isinstance(acc, dict):
                continue
            name = acc.get("name_formatted") or acc.get("name") or acc.get("domain") or "?"
            nid = "conta:" + (acc.get("name") or acc.get("domain") or "?").lower()
            add_node(nid, name, "conta",
                     domain=acc.get("domain", ""), icon=acc.get("icon", ""))
            add_edge("email", nid, "conta")

        # breaches — timeline com source=data_breach
        db = eo.get("data_breaches") or {}
        if db.get("compromised") is True:
            tl = (eo.get("meta") or {}).get("timeline") or []
            for t in tl:
                if not isinstance(t, dict) or t.get("source") != "data_breach":
                    continue
                nm = t.get("name") or "breach"
                nid = "breach:" + nm.lower()
                add_node(nid, nm, "breach", date=str(t.get("date") or "")[:10])
                add_edge("email", nid, "breach")

        # stealer log
        sl = eo.get("stealer_logs") or {}
        if sl.get("compromised") is True:
            add_node("stealer", "stealer log", "stealer")
            add_edge("email", "stealer", "stealer")

    # ── holehe: contas encontradas (site + domínio, sem foto) ──
    hh = holehe or {}
    if hh.get("ok") is not False:
        for f in (hh.get("found") or []):
            if not isinstance(f, dict):
                continue
            name = f.get("name") or f.get("domain") or "?"
            nid = "conta:" + (f.get("name") or f.get("domain") or "?").lower()
            add_node(nid, name, "conta", domain=f.get("domain", ""), icon="")
            add_edge("email", nid, "conta")

    # ── user-scanner: contas registradas (site_name + categoria + url/extra) ──
    us = userscanner or {}
    if us.get("ok") is not False:
        for f in (us.get("found") or []):
            if not isinstance(f, dict):
                continue
            name = f.get("site_name") or "?"
            url = f.get("url") or ""
            domain = urlparse(url).netloc if url else ""
            nid = "conta:" + name.lower()
            add_node(nid, name, "conta", domain=domain, icon="",
                     category=f.get("category", ""), profile_url=url,
                     extra=f.get("extra") or {}, media=f.get("media") or {})
            add_edge("email", nid, "conta")

    nodes = [{"id": "email", "label": email, "type": "email", "email": email}]
    nodes.extend(nodes_by_id.values())
    return {"seed": "email", "nodes": nodes, "edges": edges}


# ── orquestração ────────────────────────────────────────────────────────────
def lookup_email(email: str, provider: str = "all", refresh: bool = False,
                 timeout: float = 8.0, rotate: bool = True) -> dict:
    """Consulta completa. `provider`: holehe | emailosint | userscanner | both | all.

    - all   = holehe + emailosint + userscanner (padrão — roda tudo)
    - both  = holehe + emailosint
    - userscanner sozinho roda só o sweep de ~220 sites.
    """
    email = (email or "").strip().lower()
    if not is_email(email):
        raise EmailOSINTError("e-mail inválido", "invalid_email")
    provider = provider or "all"
    if provider not in ("holehe", "emailosint", "both", "userscanner", "all"):
        provider = "all"

    def _covers(cached_p: str, requested: str) -> bool:
        if cached_p == "all":
            return True
        if cached_p == "both":
            return requested in ("both", "holehe", "emailosint")
        return cached_p == requested

    cached = None if refresh else get_email_cache(email)
    if cached and cached.get("email") == email:
        # serve do cache só se cobre o provider pedido — um cache de "holehe" não
        # deve mascarar um pedido por "all"/"userscanner" (e vice-versa)
        cached_p = cached.get("provider", "both")
        if _covers(cached_p, provider):
            cached = dict(cached)
            cached["cached"] = True
            cached["graph"] = build_email_graph(
                email, cached.get("holehe"), cached.get("emailosint"),
                cached.get("userscanner"))
            return cached

    out = {"email": email, "cached": False, "provider": provider}

    if provider in ("holehe", "both", "all"):
        try:
            out["holehe"] = summarize_holehe(holehe_scan(email, timeout=timeout))
        except Exception as e:
            out["holehe"] = {"ok": False, "error": str(e), "found": [],
                             "rate_limited": [], "errors": [], "not_found": 0, "total": 0}

    if provider in ("emailosint", "both", "all"):
        try:
            # o `timeout` do endpoint é o limite por-módulo do holehe (8s default);
            # o stream SSE do emailosint é um único request longo (30s+), então usa
            # um teto próprio maior — senão o frontend (sem param timeout) mataria o stream.
            out["emailosint"] = emailosint_lookup(email, rotate=rotate,
                                                  timeout=max(timeout, 120.0))
        except EmailOSINTError as e:
            out["emailosint"] = {"ok": False, "error": str(e), "code": e.code}
        except Exception as e:
            out["emailosint"] = {"ok": False, "error": str(e)}

    if provider in ("userscanner", "all"):
        try:
            out["userscanner"] = userscanner_scan(email)
        except Exception as e:
            out["userscanner"] = {"ok": False, "error": str(e), "found": [],
                                  "not_found": 0, "errors": [], "skipped": [], "total": 0}

    out["graph"] = build_email_graph(email, out.get("holehe"), out.get("emailosint"),
                                     out.get("userscanner"))
    set_email_cache(email, out)
    return out


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else ""
    prov = sys.argv[2] if len(sys.argv) > 2 else "both"
    if not addr:
        print("uso: python email_osint.py <email> [holehe|emailosint|userscanner|both|all]")
        sys.exit(1)
    print(json.dumps(lookup_email(addr, provider=prov), ensure_ascii=False, indent=2))
