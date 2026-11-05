"""
Blind signatures: RSA (Chaum, FDH).

Two phases, two endpoints, 0 table who make the link :
  /api/issue  : email @ensc.fr + blind message     -> blind  signature (1 per email)
  /api/submit : token + signature + answer       -> stored answer    (1 per token)

The server never sees the token on transmission (he only sees m * r^e mod n),
and never sees the email at submission.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("DB_PATH", "survey.db")

KEY_PATH = Path(os.environ.get("KEY_PATH", "signing_key.pem"))
SECRET_PATH = Path(os.environ.get("SECRET_PATH", "email_hmac.secret"))

KEY_BITS = int(os.environ.get("KEY_BITS", "3072"))
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "ensc.fr")

MAX_PAYLOAD = 20_000  # octets

HEX = re.compile(r"[0-9a-f]+")
EMAIL = re.compile(rf"[a-z0-9._+-]+@{re.escape(ALLOWED_DOMAIN)}")


def load_key() -> rsa.RSAPrivateKey:
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    KEY_PATH.chmod(0o600)
    return key


def load_secret() -> bytes:
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes()
    s = secrets.token_bytes(32)
    SECRET_PATH.write_bytes(s)
    SECRET_PATH.chmod(0o600)
    return s


_key = load_key()
_nums = _key.private_numbers()
N, E, D = _nums.public_numbers.n, _nums.public_numbers.e, _nums.d
EMAIL_SECRET = load_secret()


def fdh(token: bytes, n: int) -> int:
    """Full Domain Hash : SHA-256 en mode compteur, étiré à |n| + 256 bits puis réduit mod n.
    Doit rester strictement identique côté client (static/index.html)."""
    k = (n.bit_length() + 7) // 8
    blocks = k // 32 + 2
    out = b"".join(
        hashlib.sha256(b"ensc-fdh-v1" + i.to_bytes(4, "big") + token).digest()
        for i in range(blocks)
    )
    return int.from_bytes(out, "big") % n


# ---------- base ----------
# WITHOUT ROWID : sinon SQLite garde un rowid croissant = ordre d'insertion exploitable
# pour corréler `spent` et `responses`. Ici les tables sont triées par clé (hash / UUID aléatoire).
SCHEMA = """
CREATE TABLE IF NOT EXISTS issued    (email_hash BLOB PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS spent     (token_hash BLOB PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS responses (id TEXT PRIMARY KEY,
                                      submitted_week TEXT NOT NULL,
                                      payload TEXT NOT NULL) WITHOUT ROWID;
"""

def init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.close()

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, isolation_level=None)
    try:
        con.execute("BEGIN IMMEDIATE")
        yield con
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction:
            con.execute("ROLLBACK")
        raise
    finally:
        con.close()


init_db()
app = FastAPI(docs_url=None, redoc_url=None)


def parse_hex(s: str, what: str) -> int:
    s = s.lower()
    if not HEX.fullmatch(s):
        raise HTTPException(400, f"{what} : hex invalide")
    return int(s, 16)


@app.get("/api/pubkey")
def pubkey():
    return {"n": format(N, "x"), "e": format(E, "x")}


class IssueIn(BaseModel):
    email: str = Field(max_length=254)
    blinded: str = Field(max_length=2048)


@app.post("/api/issue")
def issue(body: IssueIn):
    email = body.email.strip().lower()
    if not EMAIL.fullmatch(email):
        raise HTTPException(400, f"email @{ALLOWED_DOMAIN} requis")
    # TODO prod : vérifier ici la possession de l'email (OTP par mail) AVANT de signer.
    b = parse_hex(body.blinded, "blinded")
    if not 1 < b < N:
        raise HTTPException(400, "blinded hors domaine")

    email_hash = hmac.new(EMAIL_SECRET, email.encode(), hashlib.sha256).digest()
    with db() as con:
        try:
            con.execute("INSERT INTO issued VALUES (?)", (email_hash,))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "jeton déjà délivré pour cet email")
        sig_blind = pow(b, D, N)
    return {"blind_signature": format(sig_blind, "x")}


class SubmitIn(BaseModel):
    token: str = Field(min_length=64, max_length=64)
    signature: str = Field(max_length=2048)
    answers: dict[str, Any]


@app.post("/api/submit")
def submit(body: SubmitIn):
    token = bytes.fromhex(body.token) if HEX.fullmatch(body.token.lower()) else b""
    if len(token) != 32:
        raise HTTPException(400, "jeton invalide")
    sig = parse_hex(body.signature, "signature")
    if not 0 < sig < N or pow(sig, E, N) != fdh(token, N):
        raise HTTPException(400, "signature invalide")

    payload = json.dumps(body.answers, separators=(",", ":"), sort_keys=True)
    if len(payload.encode()) > MAX_PAYLOAD:
        raise HTTPException(413, "réponses trop volumineuses")
    # TODO prod : valider `answers` contre le schéma strict du questionnaire (pas de champ libre).

    y, w, _ = date.today().isocalendar()
    with db() as con:
        try:
            con.execute("INSERT INTO spent VALUES (?)", (hashlib.sha256(token).digest(),))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "jeton déjà utilisé")
        con.execute(
            "INSERT INTO responses VALUES (?,?,?)",
            (str(uuid.uuid4()), f"{y}-W{w:02d}", payload),
        )
    return {"ok": True}


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")