#!/usr/bin/env python3
import subprocess, base64, os, sqlite3, time, threading
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
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

HOST = "0.0.0.0"
PORT = 8081
SEARCH_DIR = "dbs/"  # diretório onde o grep vai rodar
USERNAME = os.environ.get("USERNAME", "-")
PASSWORD = os.environ.get("PASSWORD", "-")
BASE = os.path.abspath("dbs/")
PAGE_SIZE    = 5000              # linhas por página
SEARCH_LIMIT = 100000            # máximo total de linhas processadas
MAX_PER_FILE = 5000              # máximo de matches por arquivo (rg --max-count)
CACHE_DB     = "search_cache.db"
CACHE_TTL    = 10 * 24 * 3600   # 10 dias em segundos
TIMEOUT      = 60

FRONTEND_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Grep and Cat</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&amp;family=DM+Sans:wght@400;500;700&amp;display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#c9c9d6;--dim:#5a5a72;--a:#00e5a0;--ad:#00e5a020;--a2:#6c8cff;--a2d:#6c8cff20;--red:#ff4d6a}
body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center}
.hd{padding:50px 20px 20px;text-align:center}
.hd h1{font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;letter-spacing:-1px}
.hd h1 .gc{color:var(--a)} .hd h1 .cc{color:var(--a2)} .hd h1 .dm{color:var(--dim)}
.hd p{color:var(--dim);margin-top:8px;font-size:.9rem}
.ct{width:100%;max-width:900px;padding:0 20px}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:var(--surface);border-radius:10px;padding:4px;border:1px solid var(--border)}
.tab{flex:1;padding:12px 20px;background:0 0;border:none;border-radius:8px;font-family:'JetBrains Mono',monospace;font-weight:600;font-size:.9rem;color:var(--dim);cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px}
.tab:hover{color:var(--text)}
.tab.ag{background:var(--ad);color:var(--a);border:1px solid var(--a)}
.tab.ac{background:var(--a2d);color:var(--a2);border:1px solid var(--a2)}
.sb{display:flex;gap:10px;margin-bottom:16px}
.sb input{flex:1;padding:14px 18px;background:var(--surface);border:2px solid var(--border);border-radius:10px;color:#fff;font-family:'JetBrains Mono',monospace;font-size:1rem;outline:0;transition:border-color .2s,box-shadow .2s}
.sb input:focus.gf{border-color:var(--a);box-shadow:0 0 20px var(--ad)}
.sb input:focus.cf{border-color:var(--a2);box-shadow:0 0 20px var(--a2d)}
.sb input::placeholder{color:var(--dim)}
.sb button{padding:14px 28px;border:none;border-radius:10px;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.95rem;cursor:pointer;transition:transform .1s,opacity .2s;white-space:nowrap}
.sb button:hover{opacity:.85} .sb button:active{transform:scale(.97)} .sb button:disabled{opacity:.4;cursor:not-allowed}
.bg{background:var(--a);color:var(--bg)} .bc{background:var(--a2);color:#fff}
.rh{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.rh span{font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--dim)}
.st{font-family:'JetBrains Mono',monospace;font-size:.75rem;padding:4px 10px;border-radius:20px}
.st.ok{background:#00e5a018;color:var(--a)} .st.er{background:#ff4d6a18;color:var(--red)} .st.ld{background:#ffd60a18;color:#ffd60a}
.ow{position:relative;margin-bottom:12px}
.cb{position:absolute;top:10px;right:10px;background:var(--border);color:var(--dim);border:1px solid #2a2a3e;border-radius:6px;padding:6px 14px;font-family:'JetBrains Mono',monospace;font-size:.75rem;cursor:pointer;transition:all .2s;z-index:10;display:none}
.cb:hover{background:#2a2a3e;color:var(--text)}
.cb.cp{background:var(--a);color:var(--bg);border-color:var(--a)}
.out{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:40px 20px 20px;min-height:300px;max-height:70vh;overflow:auto;font-family:'JetBrains Mono',monospace;font-size:.82rem;line-height:1.7;white-space:pre-wrap;word-break:break-all;color:var(--text)}
.out::-webkit-scrollbar{width:6px} .out::-webkit-scrollbar-track{background:0 0} .out::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.out .ph{color:var(--dim);font-style:italic}
.pg{display:none;justify-content:center;align-items:center;gap:12px;margin-top:10px;margin-bottom:30px}
.pgb{background:var(--surface);color:var(--dim);border:1px solid var(--border);border-radius:6px;padding:6px 16px;font-family:'JetBrains Mono',monospace;font-size:.8rem;cursor:pointer;transition:all .2s}
.pgb:hover:not(:disabled){background:var(--border);color:var(--text)}.pgb:disabled{opacity:.3;cursor:not-allowed}
.pgi{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--dim)}
@keyframes spin{to{transform:rotate(360deg)}}
.sp{display:inline-block;width:14px;height:14px;border:2px solid #ffd60a40;border-top-color:#ffd60a;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
</style>
</head>
<body>
<div class="hd">
<h1><span class="dm">$</span> <span class="gc">rp</span> <span class="dm">&amp;</span> <span class="cc">cat</span></h1>
<p>ferramentas raw no servidor</p>
</div>
<div class="ct">
<div class="tabs">
<button class="tab ag" id="tg" onclick="sw('grep')">&#128269; grep -aEr</button>
<button class="tab" id="tc" onclick="sw('cat')">&#128196; cat</button>
</div>
<div class="sb">
<input type="text" id="q" placeholder="google.com.br" autofocus class="gf">
<button id="btn" class="bg" onclick="go()">GREP</button>
</div>
<div class="rh"><span id="info"></span><span id="sts"></span></div>
<div class="ow">
<button class="cb" id="cpb" onclick="cp()">COPY</button>
<div class="out" id="out"><span class="ph">resultados vao aparecer aqui...</span></div>
</div>
<div class="pg" id="pg">
<button class="pgb" id="pgprev" onclick="goPage(-1)">&#8592; anterior</button>
<span class="pgi" id="pginfo"></span>
<button class="pgb" id="pgnext" onclick="goPage(1)">pr&#243;xima &#8594;</button>
</div>
</div>
<script>
const D=id=>document.getElementById(id);
let mode='grep',curPage=1,totalPages=1,lastQ='';
const emptyBuf=()=>({out:'<span class="ph">resultados vao aparecer aqui...</span>',info:'',stsClass:'',stsHtml:'',page:1,totalPages:1,lastQ:'',pgDisplay:'none',pgInfo:'',pgprevDis:true,pgnextDis:true,qVal:''});
const buf={grep:emptyBuf(),cat:emptyBuf()};
function sw(m){buf[mode]={out:D('out').innerHTML,info:D('info').textContent,stsClass:D('sts').className,stsHtml:D('sts').innerHTML,page:curPage,totalPages:totalPages,lastQ:lastQ,pgDisplay:D('pg').style.display,pgInfo:D('pginfo').textContent,pgprevDis:D('pgprev').disabled,pgnextDis:D('pgnext').disabled,qVal:D('q').value};mode=m;const s=buf[m];D('out').innerHTML=s.out;D('info').textContent=s.info;D('sts').className=s.stsClass;D('sts').innerHTML=s.stsHtml;curPage=s.page;totalPages=s.totalPages;lastQ=s.lastQ;D('pg').style.display=s.pgDisplay;D('pginfo').textContent=s.pgInfo;D('pgprev').disabled=s.pgprevDis;D('pgnext').disabled=s.pgnextDis;D('q').value=s.qVal;D('tg').className='tab';D('tc').className='tab';if(m==='grep'){D('tg').className='tab ag';D('q').placeholder='google.com.br';D('q').className='gf';D('btn').className='bg';D('btn').textContent='GREP'}else{D('tc').className='tab ac';D('q').placeholder='dbs/...';D('q').className='cf';D('btn').className='bc';D('btn').textContent='CAT'}D('q').focus()}
D('q').addEventListener('keydown',e=>{if(e.key==='Enter')go()});
D('q').addEventListener('focus',()=>{D('q').classList.add(mode==='grep'?'gf':'cf')});
function goPage(d){if(d===-1&&curPage<=1||d===1&&curPage>=totalPages)return;go(curPage+d)}
function cp(){const t=D('out').textContent;if(!t)return;function ok(){const b=D('cpb');b.textContent='COPIED!';b.classList.add('cp');setTimeout(()=>{b.textContent='COPY';b.classList.remove('cp')},1500)}function fb(){const ta=document.createElement('textarea');ta.value=t;ta.style.cssText='position:fixed;opacity:0';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(ta)}if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok).catch(fb)}else{fb()}}
async function go(pg){const q=D('q').value.trim();if(!q)return;if(q!==lastQ)pg=1;lastQ=q;curPage=pg||1;const b=D('btn'),lb=mode==='grep'?'GREP':'CAT';b.disabled=true;b.textContent='...';D('sts').className='st ld';D('sts').innerHTML='<span class=sp></span>executando';D('out').innerHTML='';D('info').textContent='';D('cpb').style.display='none';D('pg').style.display='none';const t0=performance.now();try{const url=mode==='grep'?'/search?q='+encodeURIComponent(q)+'&page='+curPage:'/cat?file='+encodeURIComponent(q);const r=await fetch(url);const el=((performance.now()-t0)/1000).toFixed(2);const txt=await r.text();if(!r.ok){D('sts').className='st er';D('sts').textContent='HTTP '+r.status;D('out').textContent=txt||'Erro '+r.status;D('cpb').style.display='block';return}const tp=parseInt(r.headers.get('X-Total-Pages')||'1');const tl=parseInt(r.headers.get('X-Total-Lines')||'0');totalPages=tp;const ln=txt.split('\\n').filter(l=>l.trim()).length;D('sts').className='st ok';D('sts').textContent=r.status+' OK';const li=tl>0?tl+' linhas':ln+' linhas';const pi=tp>1?' \xb7 p\xe1g '+curPage+'/'+tp:'';D('info').textContent=li+pi+' \xb7 '+el+'s \xb7 '+(mode==='grep'?"grep -aEr '"+q+"' .":"cat "+q);D('out').textContent=txt;D('cpb').style.display='block';if(tp>1){D('pg').style.display='flex';D('pginfo').textContent='P\xe1gina '+curPage+' de '+tp;D('pgprev').disabled=curPage<=1;D('pgnext').disabled=curPage>=tp;}}catch(e){D('sts').className='st er';D('sts').textContent='ERRO';D('out').textContent='Falha:\\n'+e.message}finally{b.disabled=false;b.textContent=lb}}
</script>
</body>
</html>"""


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
    total_pages = (total_lines + PAGE_SIZE - 1) // PAGE_SIZE
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

    def _require_auth(self):
        if check_auth(self.headers):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Grep Cat"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"401 Unauthorized")
        return False

    def do_GET(self):
        if not self._require_auth():
            return
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(FRONTEND_HTML.encode("utf-8"))
            return

        if parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if parsed.path == "/search":
            params = parse_qs(parsed.query)
            query = params.get("q", [""])[0].strip()
            if not query:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Missing q parameter")
                return

            try:
                page = max(1, int(params.get("page", ["1"])[0] or "1"))
            except (ValueError, TypeError):
                page = 1

            # tenta cache primeiro
            cached = get_cached_page(query, page)
            if cached:
                content, total_pages, total_lines = cached
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("X-Total-Lines", str(total_lines))
                self.send_header("X-Total-Pages", str(total_pages))
                self.send_header("X-Current-Page", str(page))
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
                return

            def run_rg(cmd):
                r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
                return r.stdout.decode("utf-8", errors="replace")

            try:
                cmd_passwords = ["rg", "--no-heading", "--no-ignore", "-a", f"--max-count={MAX_PER_FILE}", "-g", "passwords.txt", "-e", query, SEARCH_DIR]
                cmd_root      = ["rg", "--no-heading", "--no-ignore", "-a", f"--max-count={MAX_PER_FILE}", "--max-depth", "1", "-g", "*.txt", "-e", query, SEARCH_DIR]
                with ThreadPoolExecutor(max_workers=2) as ex:
                    f1 = ex.submit(run_rg, cmd_passwords)
                    f2 = ex.submit(run_rg, cmd_root)
                    out1 = f1.result()
                    out2 = f2.result()
                lines = (out1 + out2).splitlines()
                if not lines:
                    content = "(nenhum resultado)"
                    total_pages, total_lines = 1, 0
                elif len(lines) <= PAGE_SIZE:
                    content = "\n".join(lines)
                    total_pages, total_lines = 1, len(lines)
                else:
                    # responde com pág 1 imediatamente, resto salva em background
                    content, total_pages, total_lines = cache_page1_and_schedule(query, lines)
            except subprocess.TimeoutExpired:
                content = f"ERRO: timeout ({TIMEOUT}s)"
                total_pages, total_lines = 1, 0
            except Exception as e:
                content = f"ERRO: {str(e)}"
                total_pages, total_lines = 1, 0

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Total-Lines", str(total_lines))
            self.send_header("X-Total-Pages", str(total_pages))
            self.send_header("X-Current-Page", "1")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        if parsed.path == "/cat":
            params = parse_qs(parsed.query)

            filepath = params.get("file", [""])[0].strip()
            filepath = os.path.abspath(filepath)
            if not filepath.startswith(BASE):
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Forbidden")
                return
                
            if not filepath:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Missing file parameter")
                return
            try:
                result = subprocess.run(
                    ["cat", filepath],
                    capture_output=True, timeout=300,
                )
                if result.returncode != 0:
                    output = result.stderr.decode("utf-8", errors="replace") or f"Erro ao ler: {filepath}"                                                                               
                else:
                    output = result.stdout.decode("utf-8", errors="replace") or "(arquivo vazio)" 
            except subprocess.TimeoutExpired:
                output = "ERRO: timeout (300)"
            except Exception as e:
                output = f"ERRO: {str(e)}"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(output.encode("utf-8"))
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        print(f"  {args[0]}")


if __name__ == "__main__":
    init_cache()
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
    server = HTTPServer((HOST, PORT), Handler)
    server.serve_forever()