#!/usr/bin/env python3
"""language: Python 3.12, file: vinculos.py, target: Linux (companion of server.py), stdlib only

Vínculos manuais e-mail↔CPF. O operador escava um e-mail (holehe / user-scanner /
emailosint), descobre a que CPF ele pertence e grava a ligação. Tabela `vinculos`
no mesmo vault_graph.db do grafo de CPF — chave composta (email, cpf), nota opcional.
"""
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("GRAPH_DB", "vault_graph.db")


def init():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS vinculos (
            email      TEXT NOT NULL,
            cpf        TEXT NOT NULL,
            nota       TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            PRIMARY KEY (email, cpf)
        )
    """)
    con.commit()
    con.close()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_email(email):
    return (email or "").strip().lower()


def _norm_cpf(cpf):
    return "".join(ch for ch in (cpf or "") if ch.isdigit())


def add(email, cpf, nota=""):
    """Vincula um e-mail a um CPF (upsert por (email, cpf); nota sobrescreve)."""
    email = _norm_email(email)
    cpf = _norm_cpf(cpf)
    if not email or not cpf:
        raise ValueError("email e cpf obrigatorios")
    nota = (nota or "").strip()
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO vinculos (email, cpf, nota, created_at) VALUES (?,?,?,?) "
        "ON CONFLICT(email, cpf) DO UPDATE SET nota=excluded.nota",
        (email, cpf, nota, _now()))
    con.commit()
    con.close()
    return {"email": email, "cpf": cpf, "nota": nota}


def remove(email, cpf):
    """Desfaz a ligação e-mail↔CPF. Retorna True se existia."""
    email = _norm_email(email)
    cpf = _norm_cpf(cpf)
    con = sqlite3.connect(DB_PATH)
    cur = con.execute("DELETE FROM vinculos WHERE email=? AND cpf=?", (email, cpf))
    con.commit()
    removed = cur.rowcount > 0
    con.close()
    return removed


def _rows(cur):
    return [{"email": r[0], "cpf": r[1], "nota": r[2], "created_at": r[3]}
            for r in cur.fetchall()]


def by_email(email):
    email = _norm_email(email)
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "SELECT email, cpf, nota, created_at FROM vinculos WHERE email=? "
        "ORDER BY created_at DESC", (email,))
    out = _rows(cur)
    con.close()
    return out


def by_cpf(cpf):
    cpf = _norm_cpf(cpf)
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        "SELECT email, cpf, nota, created_at FROM vinculos WHERE cpf=? "
        "ORDER BY created_at DESC", (cpf,))
    out = _rows(cur)
    con.close()
    return out
