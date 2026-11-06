#!/usr/bin/env python3
import subprocess, base64, os, sqlite3, time, threading, glob as _glob, queue as _queue
import json, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, quote
import urllib.request

def _load_env(path=".env"):
    here = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(here, path)
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

_load_env()

import cpf_enrich
import ollama_store
import email_osint
import vinculos

# Se setada, o /email delega o scan pesado pro worker da VPS (IP novo, tira o
# rate-limit do IP residencial). Vazio = roda local, como sempre.
EMAIL_WORKER_URL     = os.environ.get("EMAIL_WORKER_URL", "")
EMAIL_WORKER_TIMEOUT = float(os.environ.get("EMAIL_WORKER_TIMEOUT", "180"))

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8082"))
SEARCH_DIR           = "dbs/"
USERNAME             = os.environ.get("USERNAME_VAULT", "-")
PASSWORD             = os.environ.get("PASSWORD_VAULT", "-")
ADMIN_USER           = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS           = os.environ.get("ADMIN_PASS", "-")
BASE                 = os.path.abspath("dbs/")
FRONTEND_FILE        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "index.html")
ADMIN_FILE           = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "admin.html")
FEATURES_FILE        = os.path.join(os.environ.get("DATA_DIR", "/data"), "features.json")
FEATURES             = ("grep", "cat", "cpf", "email")
FEATURES_DEFAULT     = {"grep": True, "cat": True, "cpf": True, "email": True}
_frontend_html: bytes = b""
PAGE_SIZE            = 5000
SEARCH_LIMIT         = 100000
MAX_PER_FILE         = 5000
CACHE_DB             = os.environ.get("CACHE_DB", "search_cache.db")
CACHE_TTL            = 10 * 24 * 3600
TIMEOUT              = 120
N_WORKERS            = (os.cpu_count() or 4) * 2
CHUNKS_TTL           = 3600
LARGE_FILE_THRESHOLD = 200 * 1024 * 1024   # 200 MB → chunk próprio
LARGE_FILE_THREADS   = 2                    # rg --threads para arquivos grandes
STREAM_BATCH         = 50                   # linhas por chunk HTTP durante streaming

# --- file chunk cache ---
_chunks: list = []
_chunks_built: float = 0.0
_chunks_lock = threading.Lock()


def _build_file_chunks() -> list[dict]:
    """
    Chunking com balanceamento por tamanho:
    - Arquivos >= LARGE_FILE_THRESHOLD ganham chunk próprio com LARGE_FILE_THREADS.
    - Arquivos menores são distribuídos entre N_WORKERS buckets por tamanho (greedy),
      garantindo carga aproximadamente igual em vez de apenas igual quantidade.
    """
    root_files = sorted(_glob.glob(os.path.join(BASE, "*.txt")))
    pw_files: list[str] = []
    for dirpath, _, filenames in os.walk(BASE):
        if dirpath == BASE:
            continue
        for fname in filenames:
            if fname == "passwords.txt":
                pw_files.append(os.path.join(dirpath, fname))

    all_files = root_files + pw_files
    if not all_files:
        return []

    large: list[tuple[str, int]] = []
    small: list[tuple[str, int]] = []
    for f in all_files:
        try:
            sz = os.path.getsize(f)
        except OSError:
            sz = 0
        (large if sz >= LARGE_FILE_THRESHOLD else small).append((f, sz))

    chunks: list[dict] = []

    # Arquivos grandes: chunk individual, do maior para o menor
    for f, _ in sorted(large, key=lambda x: -x[1]):
        chunks.append({"files": [f], "threads": LARGE_FILE_THREADS})

    # Arquivos pequenos: distribuição greedy por bytes entre N_WORKERS buckets
    small.sort(key=lambda x: -x[1])
    n = max(1, N_WORKERS)
    buckets: list[list[str]] = [[] for _ in range(n)]
    bucket_sizes = [0] * n
    for f, sz in small:
        i = min(range(n), key=lambda x: bucket_sizes[x])
        buckets[i].append(f)
        bucket_sizes[i] += sz

    for bucket in buckets:
        if bucket:
            chunks.append({"files": bucket, "threads": 1})

    n_large = len(large)
    n_small = sum(1 for b in buckets if b)
    print(f"  [chunks] {len(all_files)} arquivos → {n_large} large + {n_small} small chunks")
    return chunks


def get_file_chunks() -> list[dict]:
    global _chunks, _chunks_built
    now = time.time()
    with _chunks_lock:
        if not _chunks or now - _chunks_built > CHUNKS_TTL:
            _chunks = _build_file_chunks()
            _chunks_built = now
        return _chunks


def _stream_rg(chunk: dict, query: str, out_q: "_queue.Queue[str | None]", stop: threading.Event) -> None:
    """Worker: roda rg e coloca cada linha encontrada na fila. Envia None ao terminar."""
    files   = chunk["files"]
    threads = chunk.get("threads", 1)
    cmd = [
        "rg", "--no-heading", "--no-ignore", "--no-messages",
        "-a", f"--max-count={MAX_PER_FILE}", f"--threads={threads}",
        "--line-buffered",
        "-e", query,
    ] + files
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for raw in proc.stdout:
            if stop.is_set():
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if line:
                out_q.put(line)
        proc.stdout.close()
        proc.wait()
    except Exception:
        pass
    finally:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
        out_q.put(None)  # sinaliza que este worker terminou


# --- credenciais vazadas do e-mail (busca local no vault) -------------------
_LEAK_HASH_RE = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")


def _clean_pre(s: str) -> str:
    return s.strip().rstrip(":,").strip()


def _parse_leak(line: str, email: str) -> dict | None:
    """Extrai (url, user, password) de uma linha do vault que casa com o email.

    Casa só como token completo: o alvo não pode ser substring de um email maior.
    `netinhovalasco@gmail.com` contém `ovalasco@gmail.com`, mas é OUTRO email — a
    senha `tagima28` pertence a `netinhovalasco@gmail.com`, não ao alvo. Então o
    char imediatamente antes/depois do alvo não pode ser um caractere válido de
    email (letra, dígito, `.`, `_`, `%`, `+`, `-`), senão descartamos a linha.
    """
    low = line.lower()
    ei = low.find(email)
    if ei < 0:
        return None
    # token boundary: rejeita substring de um email maior (ex.: netinhovalasco@…)
    if ei > 0 and (low[ei - 1].isalnum() or low[ei - 1] in "._%+-"):
        return None
    tail = ei + len(email)
    if tail < len(line) and (low[tail].isalnum() or low[tail] in ".-"):
        return None
    pre = line[:ei]
    post = line[ei + len(email):]
    # hash criptográfico no lugar de senha plana (bcrypt $2y$10$...)
    m = _LEAK_HASH_RE.search(line)
    if m:
        return {"url": "", "user": email, "password": m.group(0), "hash": True}
    # senha em claro: email:senha (ou url:email:senha) — o que vem logo após o email
    if post.startswith(":"):
        password = post[1:].split(":", 1)[0].split(",", 1)[0].strip()
        if password:
            return {"url": _clean_pre(pre), "user": email, "password": password, "hash": False}
    return None


def _leak_search(email: str, limit: int = 100) -> dict:
    """Grep literal (case-insensitive) do email nas bases, em paralelo, devolve as senhas."""
    email = email.strip().lower()
    query = re.escape(email)
    results: list[dict] = []
    seen: set = set()
    lock = threading.Lock()
    total = 0

    def _run(chunk: dict) -> None:
        nonlocal total
        cmd = [
            "rg", "-i", "--no-ignore", "--no-messages", "-a",
            f"--max-count={MAX_PER_FILE}", f"--threads={chunk.get('threads', 1)}",
            "--json", "-e", query,
        ] + chunk["files"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except Exception:
            return
        for raw in proc.stdout:
            try:
                obj = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("type") != "match":
                continue
            d = obj.get("data", {})
            path = (d.get("path") or {}).get("text", "")
            if path.startswith(BASE + os.sep):
                path = path[len(BASE + os.sep):]
            text = (d.get("lines") or {}).get("text", "")
            if not text:
                continue
            with lock:
                key = path + "\x00" + text
                if key in seen:
                    continue
                seen.add(key)
                parsed = _parse_leak(text, email)
                if not parsed:
                    continue
                total += 1
                if len(results) < limit:
                    results.append({"file": path, **parsed})
        proc.stdout.close()
        proc.wait()

    threads = [threading.Thread(target=_run, args=(c,), daemon=True) for c in get_file_chunks()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"email": email, "total": total, "truncated": total > limit, "results": results}


def _load_frontend() -> bytes:
    global _frontend_html
    try:
        with open(FRONTEND_FILE, "rb") as f:
            _frontend_html = f.read()
    except FileNotFoundError:
        _frontend_html = b"<h1>frontend/index.html not found</h1>"
    return _frontend_html


def init_cache():
    con = sqlite3.connect(CACHE_DB)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
        CREATE TABLE IF NOT EXISTS searches (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            query       TEXT UNIQUE,
            created_at  REAL,
            total_lines INTEGER,
            total_pages INTEGER
        );
        CREATE TABLE IF NOT EXISTS pages (
            search_id   INTEGER,
            page_number INTEGER,
            content     TEXT,
            PRIMARY KEY (search_id, page_number)
        );
    """)
    cutoff = time.time() - CACHE_TTL
    con.execute(
        "DELETE FROM pages WHERE search_id IN (SELECT id FROM searches WHERE created_at < ?)",
        (cutoff,)
    )
    con.execute("DELETE FROM searches WHERE created_at < ?", (cutoff,))
    con.commit()
    con.close()


def get_cached_page(query, page):
    con = sqlite3.connect(CACHE_DB)
    row = con.execute(
        "SELECT id, total_lines, total_pages, created_at FROM searches WHERE query=?", (query,)
    ).fetchone()
    if not row:
        con.close()
        return None
    sid, total_lines, total_pages, created_at = row
    if time.time() - created_at > CACHE_TTL:
        con.execute("DELETE FROM pages WHERE search_id=?", (sid,))
        con.execute("DELETE FROM searches WHERE id=?", (sid,))
        con.commit()
        con.close()
        return None
    page_row = con.execute(
        "SELECT content FROM pages WHERE search_id=? AND page_number=?", (sid, page)
    ).fetchone()
    con.close()
    if not page_row:
        return None
    return page_row[0], total_pages, total_lines


def _save_remaining_pages(sid, lines):
    """Background thread: salva páginas 2+ no SQLite."""
    try:
        con = sqlite3.connect(CACHE_DB)
        chunks = [lines[i:i + PAGE_SIZE] for i in range(PAGE_SIZE, len(lines), PAGE_SIZE)]
        con.executemany(
            "INSERT OR IGNORE INTO pages (search_id, page_number, content) VALUES (?,?,?)",
            [(sid, i + 2, "\n".join(chunk)) for i, chunk in enumerate(chunks)]
        )
        con.commit()
        con.close()
    except Exception:
        pass


def cache_page1_and_schedule(query, lines):
    """
    Salva página 1 + registro no SQLite imediatamente, agenda o resto em background.
    Retorna (page1_content, total_pages, total_lines).
    """
    lines = lines[:SEARCH_LIMIT]
    total_lines = len(lines)
    total_pages = max(1, (total_lines + PAGE_SIZE - 1) // PAGE_SIZE)
    page1 = "\n".join(lines[:PAGE_SIZE])
    con = sqlite3.connect(CACHE_DB)
    old = con.execute("SELECT id FROM searches WHERE query=?", (query,)).fetchone()
    if old:
        con.execute("DELETE FROM pages WHERE search_id=?", (old[0],))
        con.execute("DELETE FROM searches WHERE id=?", (old[0],))
    con.execute(
        "INSERT INTO searches (query, created_at, total_lines, total_pages) VALUES (?,?,?,?)",
        (query, time.time(), total_lines, total_pages)
    )
    sid = con.execute("SELECT id FROM searches WHERE query=?", (query,)).fetchone()[0]
    con.execute(
        "INSERT INTO pages (search_id, page_number, content) VALUES (?,?,?)",
        (sid, 1, page1)
    )
    con.commit()
    con.close()
    if total_pages > 1:
        threading.Thread(target=_save_remaining_pages, args=(sid, lines), daemon=True).start()
    return page1, total_pages, total_lines


def check_auth(headers):
    auth = headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth.split(" ")[1]).decode("utf-8")
        user, pwd = decoded.split(":", 1)
        return user == USERNAME and pwd == PASSWORD
    except Exception:
        return False


def check_admin(headers):
    auth = headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth.split(" ")[1]).decode("utf-8")
        user, pwd = decoded.split(":", 1)
        return user == ADMIN_USER and pwd == ADMIN_PASS
    except Exception:
        return False


def load_features() -> dict:
    features = dict(FEATURES_DEFAULT)
    try:
        if os.path.isfile(FEATURES_FILE):
            with open(FEATURES_FILE, "r", encoding="utf-8") as f:
                stored = json.load(f)
            for k in FEATURES:
                if isinstance(stored.get(k), bool):
                    features[k] = stored[k]
    except (OSError, json.JSONDecodeError):
        pass
    return features


def save_features(features: dict) -> None:
    try:
        os.makedirs(os.path.dirname(FEATURES_FILE), exist_ok=True)
        tmp = FEATURES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: bool(features.get(k, True)) for k in FEATURES}, f, ensure_ascii=False)
        os.replace(tmp, FEATURES_FILE)
    except OSError:
        pass


def _load_admin() -> bytes:
    try:
        with open(ADMIN_FILE, "rb") as f:
            return f.read()
    except OSError:
        return b"<html><body>admin.html ausente</body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _cors(self) -> None:
        origin = self.headers.get("Origin") or "*"
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")

    def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8", extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _reject_auth(self, realm: str):
        # Drena o body pendente (POST) antes de responder 401 — sem isso, com
        # keep-alive HTTP/1.1 o body não consumido vira request-line da próxima
        # request e o método chega corrompido (501 "Unsupported method").
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (ValueError, TypeError):
            length = 0
        if length > 0:
            try:
                self.rfile.read(length)
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{realm}"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "16")
        self.send_header("Connection", "close")
        self._cors()
        self.end_headers()
        self.wfile.write(b"401 Unauthorized")
        self.close_connection = True

    def _require_auth(self):
        if check_auth(self.headers):
            return True
        self._reject_auth("Grep Cat")
        return False

    def _require_admin(self):
        if check_admin(self.headers):
            return True
        self._reject_auth("Admin")
        return False

    def _feature_disabled(self, feature: str) -> bool:
        if not load_features().get(feature, True):
            self._send(403, json.dumps({"error": "funcionalidade desativada", "feature": feature},
                                       ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return True
        return False

    def _wchunk(self, data: bytes) -> None:
        """Escreve um chunk HTTP chunked-transfer."""
        self.wfile.write(f"{len(data):x}\r\n".encode())
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send(200, b"OK", "text/plain")
            return

        if parsed.path == "/admin":
            if not self._require_admin():
                return
            self._send(200, _load_admin(), "text/html; charset=utf-8")
            return

        if parsed.path == "/admin/features":
            if not self._require_admin():
                return
            self._send(200, json.dumps({"features": load_features()}, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if not self._require_auth():
            return

        if parsed.path in ("/", "/index.html"):
            self._send(200, _load_frontend(), "text/html; charset=utf-8")
            return

        if parsed.path == "/features":
            self._send(200, json.dumps({"features": load_features()}, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if parsed.path == "/cpf":
            if self._feature_disabled("cpf"):
                return
            params = parse_qs(parsed.query)
            cpf = re.sub(r"\D", "", params.get("q", [""])[0])
            if not cpf:
                self._send(400, b'{"error":"Missing q parameter (CPF)"}', "application/json")
                return
            try:
                depth = max(0, min(int(params.get("depth", ["3"])[0] or "3"), 4))
            except ValueError:
                depth = 3
            refresh = params.get("refresh", ["0"])[0].lower() in ("1", "true", "yes")
            try:
                max_age = float(params.get("max_age", ["21"])[0] or "21")
            except ValueError:
                max_age = 21.0
            try:
                graph = cpf_enrich.enrich_graph(cpf, depth=depth, refresh=refresh, max_age=max_age)
                graph["vinculos"] = vinculos.by_cpf(cpf)
                self._send(200, json.dumps(graph, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except cpf_enrich.CPFError as e:
                self._send(400, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            except cpf_enrich.CaptchaError as e:
                self._send(200, json.dumps({"requireCaptcha": True, "siteKey": e.sitekey,
                                            "action": e.action, "cpf": cpf},
                                           ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            return

        if parsed.path == "/graph":
            if self._feature_disabled("cpf"):
                return
            params = parse_qs(parsed.query)
            cpf = re.sub(r"\D", "", params.get("q", [""])[0])
            if not cpf:
                self._send(400, b'{"error":"Missing q parameter (CPF)"}', "application/json")
                return
            try:
                depth = max(0, min(int(params.get("depth", ["3"])[0] or "3"), 4))
            except ValueError:
                depth = 3
            graph = cpf_enrich.stored_graph(cpf, depth=depth)
            graph["vinculos"] = vinculos.by_cpf(cpf)
            self._send(200, json.dumps(graph, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if parsed.path == "/vinculos":
            params = parse_qs(parsed.query)
            cpf = re.sub(r"\D", "", params.get("cpf", [""])[0])
            email = params.get("email", [""])[0].strip().lower()
            if cpf:
                out = vinculos.by_cpf(cpf)
            elif email:
                out = vinculos.by_email(email)
            else:
                self._send(400, b'{"error":"informe cpf= ou email="}', "application/json")
                return
            self._send(200, json.dumps({"vinculos": out}, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if parsed.path == "/ollama":
            params = parse_qs(parsed.query)
            try:
                page = max(1, int(params.get("page", ["1"])[0] or "1"))
            except (ValueError, TypeError):
                page = 1
            try:
                per_page = max(1, min(int(params.get("per_page", ["10"])[0] or "10"), 200))
            except (ValueError, TypeError):
                per_page = 10
            q = params.get("q", [""])[0].strip()
            hosts, total = ollama_store.list_hosts(page=page, per_page=per_page, q=q)
            pages = max(1, (total + per_page - 1) // per_page)
            data = {
                "stats": ollama_store.stats(),
                "hosts": hosts,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": pages,
            }
            self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if parsed.path == "/email":
            if self._feature_disabled("email"):
                return
            params = parse_qs(parsed.query)
            q = params.get("q", [""])[0].strip()
            if not q:
                self._send(400, b'{"error":"Missing q parameter (email)"}', "application/json")
                return
            provider = params.get("provider", ["all"])[0].strip().lower() or "all"
            refresh = params.get("refresh", ["0"])[0].lower() in ("1", "true", "yes")
            rotate = params.get("rotate", ["1"])[0].lower() not in ("0", "false", "no")
            try:
                timeout = max(2.0, min(float(params.get("timeout", ["8"])[0] or "8"), 30.0))
            except (ValueError, TypeError):
                timeout = 8.0
            if EMAIL_WORKER_URL:
                # delega o scan pro worker da VPS; o cache local segue intacto.
                wq = (EMAIL_WORKER_URL.rstrip("/") + "/email?q=" + quote(q)
                      + "&provider=" + quote(provider)
                      + ("&refresh=1" if refresh else "")
                      + ("&rotate=0" if not rotate else ""))
                try:
                    with urllib.request.urlopen(wq, timeout=EMAIL_WORKER_TIMEOUT) as resp:
                        body = resp.read()
                        code = resp.getcode()
                    # injeta os vínculos manuais e-mail↔CPF (persistidos localmente)
                    try:
                        data = json.loads(body.decode("utf-8", "replace"))
                        if isinstance(data, dict):
                            data["vinculos"] = vinculos.by_email(q)
                        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                    except Exception:
                        pass
                    self._send(code, body, "application/json; charset=utf-8")
                except Exception as e:
                    self._send(502, json.dumps(
                        {"error": "email-worker indisponível: %s" % e},
                        ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")
                return
            try:
                data = email_osint.lookup_email(q, provider=provider, refresh=refresh,
                                                timeout=timeout, rotate=rotate)
                data["vinculos"] = vinculos.by_email(q)
                self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except email_osint.EmailOSINTError as e:
                self._send(400, json.dumps({"error": str(e), "code": e.code},
                                           ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            return

        if parsed.path == "/email/leaks":
            if self._feature_disabled("email"):
                return
            params = parse_qs(parsed.query)
            q = params.get("q", [""])[0].strip()
            if not q:
                self._send(400, b'{"error":"Missing q parameter (email)"}', "application/json")
                return
            try:
                limit = max(1, min(int(params.get("limit", ["100"])[0] or "100"), 500))
            except (ValueError, TypeError):
                limit = 100
            try:
                data = _leak_search(q, limit=limit)
                self._send(200, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            return

        if parsed.path == "/search":
            if self._feature_disabled("grep"):
                return
            params = parse_qs(parsed.query)
            query = params.get("q", [""])[0].strip()
            if not query:
                self._send(400, b"Missing q parameter")
                return

            try:
                page = max(1, int(params.get("page", ["1"])[0] or "1"))
            except (ValueError, TypeError):
                page = 1

            # Cache hit: responde direto sem streaming
            cached = get_cached_page(query, page)
            if cached:
                content, total_pages, total_lines = cached
                body = content.encode("utf-8")
                self._send(200, body, "text/plain; charset=utf-8", {
                    "X-Total-Lines": str(total_lines),
                    "X-Total-Pages": str(total_pages),
                    "X-Current-Page": str(page),
                })
                return

            # Cache miss: streaming linha a linha via fila compartilhada
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("X-Stream", "1")
            self.end_headers()

            all_lines: list[str] = []
            stop = threading.Event()
            out_q: _queue.Queue = _queue.Queue()
            chunks = get_file_chunks()

            for chunk in chunks:
                threading.Thread(
                    target=_stream_rg,
                    args=(chunk, query, out_q, stop),
                    daemon=True,
                ).start()

            n_workers = len(chunks)
            finished  = 0
            buf: list[str] = []
            deadline  = time.time() + TIMEOUT

            try:
                while finished < n_workers and len(all_lines) + len(buf) < SEARCH_LIMIT:
                    wait = max(0.1, deadline - time.time())
                    try:
                        item = out_q.get(timeout=wait)
                    except _queue.Empty:
                        break  # timeout global

                    if item is None:
                        finished += 1
                        if buf:
                            all_lines.extend(buf)
                            self._wchunk(("\n".join(buf) + "\n").encode("utf-8"))
                            buf = []
                    else:
                        buf.append(item)
                        if len(buf) >= STREAM_BATCH:
                            all_lines.extend(buf)
                            self._wchunk(("\n".join(buf) + "\n").encode("utf-8"))
                            buf = []

                if buf:  # flush do que sobrou
                    all_lines.extend(buf)
                    self._wchunk(("\n".join(buf) + "\n").encode("utf-8"))

            except (BrokenPipeError, ConnectionResetError):
                stop.set()
                return
            except Exception as e:
                self._wchunk(f"ERRO: {e}\n".encode("utf-8"))
            finally:
                stop.set()

            total_lines = len(all_lines)
            self._wchunk(f"__EOF__{total_lines}\n".encode("utf-8"))
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

            if all_lines:
                threading.Thread(
                    target=cache_page1_and_schedule,
                    args=(query, all_lines),
                    daemon=True,
                ).start()
            return

        if parsed.path == "/cat":
            if self._feature_disabled("cat"):
                return
            params = parse_qs(parsed.query)
            raw = params.get("file", [""])[0].strip()
            if not raw:
                self._send(400, b"Missing file parameter")
                return

            # Aceita qualquer prefixo de path e normaliza para relativo ao BASE
            for prefix in (BASE + "/", BASE + os.sep, "/app/dbs/", "/dbs/", "dbs/"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
                    break
            raw = raw.lstrip("/")

            resolved = os.path.normpath(os.path.join(BASE, raw))
            if not resolved.startswith(BASE):
                self._send(403, b"Forbidden")
                return

            # Se o arquivo exato não existe, tenta glob (nomes têm sufixo de metadata)
            if not os.path.isfile(resolved):
                pattern = os.path.join(BASE, _glob.escape(raw) + "*")
                matches = sorted(_glob.glob(pattern))
                if not matches:
                    self._send(404, f"Arquivo não encontrado: {raw}".encode("utf-8"))
                    return
                resolved = os.path.normpath(matches[0])
                if not resolved.startswith(BASE):
                    self._send(403, b"Forbidden")
                    return

            try:
                with open(resolved, "rb") as f:
                    data = f.read()
                output = data.decode("utf-8", errors="replace") or "(arquivo vazio)"
            except PermissionError:
                output = f"ERRO: sem permissão para ler: {resolved}"
            except Exception as e:
                output = f"ERRO: {e}"
            self._send(200, output.encode("utf-8"),
                       extra_headers={"X-File": resolved})
            return

        self._send(404, b"404 Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/admin/features":
            if not self._require_admin():
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                n = 0
            raw = self.rfile.read(n) if n else b""
            try:
                req = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, b'{"error":"JSON invalido"}', "application/json")
                return
            feature = str(req.get("feature", "")).strip().lower()
            enabled = bool(req.get("enabled"))
            if feature not in FEATURES:
                self._send(400, json.dumps({"error": "feature invalida", "features": list(FEATURES)},
                                           ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            features = load_features()
            features[feature] = enabled
            save_features(features)
            self._send(200, json.dumps({"features": features}, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if not self._require_auth():
            return

        if parsed.path == "/cpf/resolver":
            if self._feature_disabled("cpf"):
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                n = 0
            raw = self.rfile.read(n) if n else b""
            try:
                req = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, b'{"error":"JSON invalido"}', "application/json")
                return
            cpf = re.sub(r"\D", "", str(req.get("cpf", "")))
            token = str(req.get("token", "")).strip()
            if not cpf or not token:
                self._send(400, b'{"error":"cpf e token obrigatorios"}', "application/json")
                return
            try:
                depth = max(0, min(int(req.get("depth", 3) or 3), 4))
            except (ValueError, TypeError):
                depth = 3
            refresh = str(req.get("refresh", "")).lower() in ("1", "true", "yes")
            try:
                max_age = float(req.get("max_age", 21) or 21)
            except (ValueError, TypeError):
                max_age = 21.0
            try:
                client = cpf_enrich.QBClient()
                if not client.verificar_humano(token):
                    self._send(400, b'{"error":"verificacao de humano falhou"}', "application/json")
                    return
                graph = cpf_enrich.enrich_graph(cpf, depth=depth, refresh=refresh, max_age=max_age)
                graph["vinculos"] = vinculos.by_cpf(cpf)
                self._send(200, json.dumps(graph, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except cpf_enrich.CPFError as e:
                self._send(400, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            except cpf_enrich.CaptchaError as e:
                self._send(200, json.dumps({"requireCaptcha": True, "siteKey": e.sitekey,
                                            "action": e.action, "cpf": cpf},
                                           ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}).encode("utf-8"),
                           "application/json; charset=utf-8")
            return

        if parsed.path in ("/vinculos", "/vinculos/remove"):
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                n = 0
            raw = self.rfile.read(n) if n else b""
            try:
                req = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, b'{"error":"JSON invalido"}', "application/json")
                return
            email = str(req.get("email", "")).strip().lower()
            cpf = re.sub(r"\D", "", str(req.get("cpf", "")))
            if not email or not cpf:
                self._send(400, b'{"error":"email e cpf obrigatorios"}', "application/json")
                return
            try:
                if parsed.path == "/vinculos/remove":
                    ok = vinculos.remove(email, cpf)
                else:
                    vinculos.add(email, cpf, str(req.get("nota", "")))
                    ok = True
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            self._send(200, json.dumps({"ok": bool(ok)}, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        if parsed.path == "/ollama/ingest":
            try:
                n = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                n = 0
            raw = self.rfile.read(n) if n else b""
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, b'{"error":"JSON invalido"}', "application/json")
                return
            hosts, models = ollama_store.ingest_payload(payload)
            self._send(200, json.dumps({"ok": True, "hosts": hosts, "models": models},
                                       ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")
            return

        self._send(404, b'{"error":"not found"}', "application/json")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin") or "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        print(f"  {args[0]}")


if __name__ == "__main__":
    init_cache()
    ollama_store.init()
    email_osint.init_email_cache()
    vinculos.init()
    _load_frontend()
    threading.Thread(target=get_file_chunks, daemon=True).start()  # pré-lista em background
    d = os.path.abspath(SEARCH_DIR)
    print()
    print("  +--------------------------------------+")
    print("  |  grep & cat server                    |")
    print("  +--------------------------------------+")
    print(f"  |  URL:   http://localhost:{PORT}          |")
    print(f"  |  Auth:  {USERNAME} / {PASSWORD}           |")
    print(f"  |  Dir:   {d:<28s}|")
    print("  +--------------------------------------+")
    print("  |  GET /search?q=TERMO   > grep -aEr   |")
    print("  |  GET /cat?file=PATH    > cat          |")
    print("  +--------------------------------------+")
    print()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()
