import math
import os
import secrets
import sqlite3
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update(
    DB_PATH=f"{_tmp}/t.db", KEY_PATH=f"{_tmp}/k.pem",
    SECRET_PATH=f"{_tmp}/h.secret", KEY_BITS="2048",
)

from fastapi.testclient import TestClient  # noqa: E402
import server  # noqa: E402

c = TestClient(server.app)
pub = c.get("/api/pubkey").json()
n, e = int(pub["n"], 16), int(pub["e"], 16)


def get_cred(email):
    token = secrets.token_bytes(32)
    m = server.fdh(token, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = m * pow(r, e, n) % n
    resp = c.post("/api/issue", json={"email": email, "blinded": format(blinded, "x")})
    if resp.status_code != 200:
        return resp, None
    s = int(resp.json()["blind_signature"], 16) * pow(r, -1, n) % n
    assert pow(s, e, n) == m          # signature valide après dé-aveuglement
    assert blinded != m               # le serveur n'a jamais vu m
    return resp, (token.hex(), format(s, "x"))


def submit(cred, answers=None):
    return c.post("/api/submit", json={
        "token": cred[0], "signature": cred[1], "answers": answers or {"sleep": 3, "load": 4},
    })


def test_happy_path_and_replay():
    _, cred = get_cred("alice.a@ensc.fr")
    assert submit(cred).status_code == 200
    assert submit(cred).status_code == 409          # rejeu refusé


def test_one_issuance_per_email_case_insensitive():
    assert get_cred("bob.b@ensc.fr")[0].status_code == 200
    assert get_cred("Bob.B@ENSC.fr")[0].status_code == 409


def test_domain_enforced():
    assert get_cred("eve@gmail.com")[0].status_code == 400


def test_forgery_rejected():
    _, (tok, _) = get_cred("carol.c@ensc.fr")
    assert submit((tok, format(secrets.randbelow(n), "x"))).status_code == 400
    assert submit((secrets.token_hex(32), "1")).status_code == 400


def test_signature_not_transferable_between_tokens():
    _, (t1, s1) = get_cred("dave.d@ensc.fr")
    assert submit((secrets.token_hex(32), s1)).status_code == 400


def test_no_linkage_columns():
    con = sqlite3.connect(os.environ["DB_PATH"])
    cols = {t: [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
            for t in ("issued", "spent", "responses")}
    assert cols["issued"] == ["email_hash"]
    assert cols["spent"] == ["token_hash"]
    assert cols["responses"] == ["id", "submitted_week", "payload"]
    
    # aucune table ne contient à la fois une donnée d'identité et une donnée de réponse/jeton