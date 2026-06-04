#!/usr/bin/env python3
import subprocess, base64, os, sqlite3, time, threading, glob as _glob, queue as _queue
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

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

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = 8081
SEARCH_DIR           = "dbs/"
USERNAME             = os.environ.get("USERNAME_VAULT", "-")
PASSWORD             = os.environ.get("PASSWORD_VAULT", "-")
BASE                 = os.path.abspath("dbs/")
FRONTEND_FILE        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "index.html")
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8", extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _require_auth(self):
        if check_auth(self.headers):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Grep Cat"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "16")
        self.end_headers()
        self.wfile.write(b"401 Unauthorized")
        return False

    def _wchunk(self, data: bytes) -> None:
        """Escreve um chunk HTTP chunked-transfer."""
        self.wfile.write(f"{len(data):x}\r\n".encode())
        self.wfile.write(data)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def do_GET(self):
        if not self._require_auth():
            return
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            self._send(200, _load_frontend(), "text/html; charset=utf-8")
            return

        if parsed.path == "/health":
            self._send(200, b"OK", "text/plain")
            return

        if parsed.path == "/search":
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

    def log_message(self, format, *args):
        print(f"  {args[0]}")


if __name__ == "__main__":
    init_cache()
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
