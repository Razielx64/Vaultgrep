#!/usr/bin/env python3
# language: Python 3, target: cross-platform
"""Persistência do inventário de instâncias Ollama expostas (worker da VPS).

Recebe o payload do scanner (um host ou uma lista) e faz upsert em SQLite.
Hosts: chave (ip, port), com geo/org do Shodan + flags. Modelos: 1:N por host.
"""
import os
import json
import sqlite3
import threading
from datetime import datetime, timezone

OLLAMA_DB = os.environ.get("OLLAMA_DB", "ollama.db")

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect():
    con = sqlite3.connect(OLLAMA_DB)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    return con


def init() -> None:
    with _lock:
        con = _connect()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS ollama_hosts (
                ip          TEXT NOT NULL,
                port        INTEGER NOT NULL,
                country     TEXT,
                org         TEXT,
                asn         TEXT,
                lat         REAL,
                lon         REAL,
                alive       INTEGER DEFAULT 0,
                model_count INTEGER DEFAULT 0,
                flags       TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                PRIMARY KEY (ip, port)
            );
            CREATE TABLE IF NOT EXISTS ollama_models (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                ip             TEXT NOT NULL,
                port           INTEGER NOT NULL,
                name           TEXT,
                size_bytes     INTEGER,
                parameter_size TEXT,
                family         TEXT,
                parent_model   TEXT,
                quantization   TEXT,
                context_length INTEGER,
                capabilities   TEXT,
                remote_host    TEXT,
                flags          TEXT,
                live           INTEGER DEFAULT 0,
                response       TEXT,
                last_seen      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ollama_models_host ON ollama_models (ip, port);
            CREATE INDEX IF NOT EXISTS idx_ollama_hosts_seen ON ollama_hosts (last_seen DESC);
        """)
        con.commit()
        con.close()


def _clean_host(raw: dict) -> dict:
    """Normaliza o payload de um host; devolve None se não há (ip, port)."""
    ip = str(raw.get("ip") or "").strip()
    if not ip:
        return None
    try:
        port = int(raw.get("port") or 11434)
    except (ValueError, TypeError):
        port = 11434
    return {
        "ip": ip,
        "port": port,
        "country": str(raw.get("country") or ""),
        "org": str(raw.get("org") or ""),
        "asn": str(raw.get("asn") or ""),
        "lat": raw.get("lat"),
        "lon": raw.get("lon"),
        "alive": 1 if raw.get("alive") else 0,
        "model_count": int(raw.get("model_count") or 0),
        "flags": json.dumps(raw.get("flags") or [], ensure_ascii=False),
        "first_seen": str(raw.get("scanned_at") or _now()),
        "last_seen": str(raw.get("scanned_at") or _now()),
        "models": raw.get("models") or [],
    }


def ingest(raw: dict) -> tuple[int, int]:
    """Faz upsert de um host e substitui seus modelos. Retorna (hosts, models)."""
    host = _clean_host(raw)
    if host is None:
        return 0, 0

    models = host.pop("models", [])
    now = _now()
    host["last_seen"] = now

    with _lock:
        con = _connect()
        try:
            con.execute("""
                INSERT INTO ollama_hosts
                    (ip, port, country, org, asn, lat, lon, alive, model_count, flags, first_seen, last_seen)
                VALUES
                    (:ip, :port, :country, :org, :asn, :lat, :lon, :alive, :model_count, :flags, :first_seen, :last_seen)
                ON CONFLICT(ip, port) DO UPDATE SET
                    country=excluded.country, org=excluded.org, asn=excluded.asn,
                    lat=excluded.lat, lon=excluded.lon, alive=excluded.alive,
                    model_count=excluded.model_count, flags=excluded.flags,
                    last_seen=excluded.last_seen
            """, host)
            con.execute("DELETE FROM ollama_models WHERE ip=? AND port=?", (host["ip"], host["port"]))

            n_models = 0
            for m in models or []:
                name = str(m.get("name") or m.get("model") or "").strip()
                if not name:
                    continue
                live = 1 if m.get("live") else 0
                con.execute("""
                    INSERT INTO ollama_models
                        (ip, port, name, size_bytes, parameter_size, family, parent_model,
                         quantization, context_length, capabilities, remote_host, flags, live, response, last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    host["ip"], host["port"], name,
                    int(m.get("size_bytes") or 0),
                    str(m.get("parameter_size") or ""),
                    str(m.get("family") or ""),
                    str(m.get("parent_model") or ""),
                    str(m.get("quantization") or ""),
                    int(m.get("context_length") or 0),
                    json.dumps(m.get("capabilities") or [], ensure_ascii=False),
                    str(m.get("remote_host") or ""),
                    json.dumps(m.get("flags") or [], ensure_ascii=False),
                    live,
                    str(m.get("response") or ""),
                    now,
                ))
                n_models += 1
            con.commit()
        finally:
            con.close()
    return 1, n_models


def ingest_payload(payload) -> tuple[int, int]:
    """Aceita uma lista de hosts, um dict {hosts:[...]}, {results:[...]} ou um host único."""
    hosts = []
    if isinstance(payload, list):
        hosts = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("hosts"), list):
            hosts = payload["hosts"]
        elif isinstance(payload.get("results"), list):
            hosts = payload["results"]
        elif payload.get("ip"):
            hosts = [payload]
    total_h, total_m = 0, 0
    for h in hosts:
        if isinstance(h, dict):
            nh, nm = ingest(h)
            total_h += nh
            total_m += nm
    return total_h, total_m


def _loads(s, default):
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


def list_hosts(page: int = 1, per_page: int = 10, q: str = "") -> tuple[list[dict], int]:
    """Pagina e filtra o inventário. Retorna (hosts, total)."""
    page = max(1, int(page or 1))
    per_page = max(1, min(int(per_page or 10), 200))
    q = (q or "").strip()

    where = ""
    args: list = []
    if q:
        like = f"%{q}%"
        where = """
            WHERE h.ip LIKE ? OR h.org LIKE ? OR h.country LIKE ? OR h.asn LIKE ?
               OR EXISTS (SELECT 1 FROM ollama_models m
                           WHERE m.ip = h.ip AND m.port = h.port AND m.name LIKE ?)
        """
        args = [like, like, like, like, like]

    with _lock:
        con = _connect()
        try:
            total = con.execute(
                f"SELECT COUNT(*) FROM ollama_hosts h {where}", args).fetchone()[0]
            hosts = con.execute(f"""
                SELECT h.ip, h.port, h.country, h.org, h.asn, h.lat, h.lon,
                       h.alive, h.model_count, h.flags, h.first_seen, h.last_seen
                FROM ollama_hosts h {where}
                ORDER BY h.last_seen DESC
                LIMIT ? OFFSET ?
            """, args + [per_page, (page - 1) * per_page]).fetchall()

            models: list = []
            if hosts:
                keys = [f"{r[0]}:{r[1]}" for r in hosts]
                ph = ",".join("?" * len(keys))
                models = con.execute(f"""
                    SELECT ip, port, name, size_bytes, parameter_size, family, parent_model,
                           quantization, context_length, capabilities, remote_host, flags, live, response, last_seen
                    FROM ollama_models
                    WHERE (ip || ':' || port) IN ({ph})
                    ORDER BY id
                """, keys).fetchall()
        finally:
            con.close()

    by_host: dict = {}
    for h in hosts:
        by_host[(h[0], h[1])] = {
            "ip": h[0], "port": h[1], "country": h[2], "org": h[3], "asn": h[4],
            "lat": h[5], "lon": h[6], "alive": h[7], "model_count": h[8],
            "flags": _loads(h[9], []), "first_seen": h[10], "last_seen": h[11],
            "models": [],
        }
    for m in models:
        key = (m[0], m[1])
        if key in by_host:
            by_host[key]["models"].append({
                "name": m[2], "size_bytes": m[3], "parameter_size": m[4], "family": m[5],
                "parent_model": m[6], "quantization": m[7], "context_length": m[8],
                "capabilities": _loads(m[9], []), "remote_host": m[10],
                "flags": _loads(m[11], []), "live": m[12], "response": m[13], "last_seen": m[14],
            })
    return list(by_host.values()), total


def stats() -> dict:
    with _lock:
        con = _connect()
        try:
            hosts = con.execute("SELECT COUNT(*), COALESCE(SUM(model_count),0) FROM ollama_hosts").fetchone()
            models = con.execute("SELECT COUNT(*), COALESCE(SUM(live),0) FROM ollama_models").fetchone()
        finally:
            con.close()
    return {
        "hosts": hosts[0],
        "models": models[0],
        "live_models": models[1],
        "model_slots": hosts[1],
    }
