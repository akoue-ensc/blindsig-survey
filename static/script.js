"use strict";
// ---------- garde-fous : plus d'échec silencieux ----------
const showErr = m => { const el = document.getElementById("msg"); if (el) el.textContent = "Erreur : " + m; };
window.addEventListener("error", e => showErr(e.message));
window.addEventListener("unhandledrejection", e => showErr((e.reason && e.reason.message) || e.reason));
if (location.protocol === "file:") showErr("ouvre la page via le serveur (http://127.0.0.1:8000), pas en double-cliquant sur le fichier");
else if (!window.crypto || !crypto.subtle) showErr("contexte non sécurisé : utilise http://127.0.0.1:8000 ou http://localhost:8000 (pas l'IP ou le nom de la machine)");
// ---------- primitives BigInt ----------
const enc = new TextEncoder();
const hex = u8 => [...u8].map(x => x.toString(16).padStart(2, "0")).join("");
const big = u8 => BigInt("0x" + (hex(u8) || "0"));

function modpow(b, e, m) {
  let r = 1n; b %= m;
  while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; }
  return r;
}
function modinv(a, m) {                       // Euclide étendu ; lève si gcd != 1
  let [r0, r1] = [m, a % m], [t0, t1] = [0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1]; }
  if (r0 !== 1n) throw new Error("non inversible");
  return ((t0 % m) + m) % m;
}
function randBelow(n) {                        // |n| + 64 bits puis mod : biais négligeable
  const k = Math.ceil(n.toString(2).length / 8) + 8;
  return big(crypto.getRandomValues(new Uint8Array(k))) % n;
}
async function fdh(token, n) {                 // identique à server.fdh
  const k = Math.ceil(n.toString(2).length / 8);
  const blocks = Math.floor(k / 32) + 2;
  const parts = [];
  for (let i = 0; i < blocks; i++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, i);
    const buf = new Uint8Array([...enc.encode("ensc-fdh-v1"), ...ctr, ...token]);
    parts.push(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)));
  }
  return big(parts.flatMap(p => [...p])) % n;
}

// ---------- protocole ----------
async function obtainCredential(email) {
  const pub = await (await fetch("/api/pubkey")).json();
  const n = BigInt("0x" + pub.n), e = BigInt("0x" + pub.e);

  const token = crypto.getRandomValues(new Uint8Array(32));
  const m = await fdh(token, n);

  let r, rinv;
  for (;;) { r = randBelow(n); if (r < 2n) continue; try { rinv = modinv(r, n); break; } catch {} }

  const blinded = m * modpow(r, e, n) % n;     // m' = m · r^e
  const res = await fetch("/api/issue", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, blinded: blinded.toString(16) }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || res.status);
  const sBlind = BigInt("0x" + (await res.json()).blind_signature);

  const s = sBlind * rinv % n;                 // s = s' · r^-1 = m^d
  if (modpow(s, e, n) !== m) throw new Error("signature reçue invalide");
  return hex(token) + "." + s.toString(16);
}

// ---------- UI ----------
const $ = id => document.getElementById(id);
const say = t => { $("msg").textContent = t; };
const KEY = "cred";

function showStep2(cred) {
  localStorage.setItem(KEY, cred);
  // fragment : jamais envoyé au serveur, donc absent des logs
  history.replaceState(null, "", "#" + cred);
  $("resume").textContent = location.href;
  $("step1").classList.add("hidden");
  $("step2").classList.remove("hidden");
}

(function boot() {
  const cred = location.hash.slice(1) || localStorage.getItem(KEY);
  if (/^[0-9a-f]{64}\.[0-9a-f]+$/.test(cred || "")) showStep2(cred);
})();

$("get").onclick = async () => {
  try {
    say("Calcul…");
    showStep2(await obtainCredential($("email").value.trim()));
    say("");
  } catch (e) { say("Erreur : " + e.message); }
};

$("send").onclick = async () => {
  const answers = {};
  for (const name of ["sleep", "load"]) {
    const el = document.querySelector(`input[name=${name}]:checked`);
    if (!el) return say("Réponds à toutes les questions.");
    answers[name] = Number(el.value);
  }
  const [token, signature] = (location.hash.slice(1) || localStorage.getItem(KEY)).split(".");
  const res = await fetch("/api/submit", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, signature, answers }),
  });
  if (res.ok) {
    localStorage.removeItem(KEY);
    history.replaceState(null, "", location.pathname);
    $("step2").classList.add("hidden");
    say("Merci, réponse enregistrée.");
  } else say("Erreur : " + ((await res.json()).detail || res.status));
};