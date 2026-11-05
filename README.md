# blindsig-survey

Proof of concept of an anonymous survey with **one response per person**, no login, and no way for the server to link a response to an email. 
Built on RSA blind signatures (Chaum, full-domain hash).

> [!IMPORTANT]
> **Status: PoC, not audited. Do not use in production.**
> Hand-rolled RSA-FDH blind signatures, not RFC 9474. Email ownership is not verified yet (see `TODO` in `server.py`).

## How it works

Two phases, no table linking them.

```
Phase 1 - issuance (needs your @ensc.fr email)
  browser: t = random(32 bytes), m = FDH(t), m' = m * r^e     (r random, secret)
  browser ---- email, m' ---->  server   checks email, one token per email
  browser <--- s' = m'^d ----   server   signs without seeing t
  browser: s = s' * r^-1 = m^d            (valid signature on t)

Phase 2 - submission (no email)
  browser ---- t, s, answers ---->  server   checks s^e == FDH(t), t unused
                                             stores answers, marks t spent
```

- At issuance the server sees the email and `m'`, never `t`: `m'` is uniformly random because of `r`.
- At submission the server sees `t` and the answers, never the email.
- `t` and `s` live in the URL fragment (`#t.s`), so a response can be sent from another device and nothing sensitive reaches server logs.

| Table       | Contains                      | Purpose                |
|-------------|-------------------------------|------------------------|
| `issued`    | `HMAC(secret, email)`         | one token per person   |
| `spent`     | `SHA256(t)`                   | one response per token |
| `responses` | random UUID, ISO week, JSON   | the answers            |

No foreign keys, no timestamps finer than a week, and `WITHOUT ROWID` tables so insertion order cannot be used to correlate rows.

## Run

```bash
pip install -r requirements.txt
pytest -q
uvicorn server:app --no-access-log    # no access log: no IPs stored
```

Open `http://127.0.0.1:8000`. The signing key (`signing_key.pem`) and HMAC secret (`email_hmac.secret`) are generated on first start and git-ignored.
Environment variables: `DB_PATH`, `KEY_PATH`, `SECRET_PATH`, `KEY_BITS` (default 3072), `ALLOWED_DOMAIN` (default `ensc.fr`).

## Limits

- `issued` reveals **who participated**, not what they answered.
- A lost token cannot be reissued (that is what "one per person" costs).
- Network metadata (IP, timing) can still correlate the two phases: disable proxy logs, submit later or from another network.
- Cryptography does not stop re-identification through quasi-identifiers on a small cohort: use coarse answer buckets, avoid free text, apply a k-anonymity threshold when analysing.
- Mental-health data is special-category data under GDPR: consult your DPO before any real collection.

## TODO

- Email OTP before signing
- Strict schema validation of `answers`
- Switch to a vetted RFC 9474 (RSABSSA) implementation
