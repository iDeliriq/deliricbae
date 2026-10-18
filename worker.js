// Worker Aurum (site + licente).
// - serveste site-ul static (binding ASSETS)
// - Rapoarte: protejate cu SITE_PASSWORD (cookie semnat HMAC "dbsess").
//     /api/login, /api/logout, /api/publish (X-Publish-Key), /api/reports
// - Unelte (tools): baza de date editabila de admin, in KV cheia "tools_db".
//     GET /api/tools (public) ; POST /api/tools (doar admin) ;
//     /api/admin/login, /api/admin/logout, /api/admin/me (secret ADMIN_PASSWORD, cookie "dbadm")
// Secretele (SITE_PASSWORD, ADMIN_PASSWORD) stau in Cloudflare, niciodata in cod.

const SESS = "dbsess";     // cookie vizitator rapoarte
const ADM = "dbadm";       // cookie admin
const MAX_AGE = 7 * 24 * 3600;
const enc = new TextEncoder();

const DEMO = {
  generated_at: 0, player: "",
  totals: { sessions: 0, yang: 0, kills: 0, seconds: 0, loot_value: 0 },
  daily: [], top_loot: [], days: [], empty: true,
};

// structura initiala a Uneltelor (pana cand adminul o editeaza)
const DEFAULT_TOOLS = {
  v: 1, updated_at: 0,
  cats: [
    { id: "c_arme", name: "Arme", order: 10 },
    { id: "c_armuri", name: "Armuri", order: 20 },
    { id: "c_acc", name: "Accesorii", order: 30 },
    { id: "c_mat", name: "Materiale", order: 90 },
  ],
  mats: [
    { id: "m_sul", name: "Sul binecuvântat", vnum: 25040, price: 46000 },
    { id: "m_piatra", name: "Piatră magică", vnum: 25041, price: 120000 },
  ],
  items: [
    {
      id: "i_demo", cat: "c_arme", name: "Exemplu +9 (șterge-mă)", icon: 0,
      desc: "Item exemplu — editează-l sau șterge-l din tab-ul Admin.",
      kind: "upgrade", recipe: [],
      levels: [
        { to: 1, tax: 20000, chance: 100, mats: [{ m: "m_sul", q: 1 }] },
        { to: 2, tax: 30000, chance: 100, mats: [{ m: "m_sul", q: 1 }] },
        { to: 3, tax: 40000, chance: 90, mats: [{ m: "m_sul", q: 2 }, { m: "m_piatra", q: 1 }] },
      ],
    },
  ],
};

// ---------- limita de incercari la login (pe IP) ----------
// max LOGIN_MAX parole gresite in LOGIN_WINDOW secunde; apoi 429 pana trece fereastra.
const LOGIN_MAX = 5, LOGIN_WINDOW = 15 * 60;

function clientIp(req) {
  return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "local";
}

async function loginBlocked(env, req, scope) {
  if (!env.DB) return false;
  const raw = await env.DB.get(`rl:${scope}:${clientIp(req)}`);
  if (!raw) return false;
  try { const o = JSON.parse(raw); return o.n >= LOGIN_MAX && Date.now() / 1000 - o.t0 < LOGIN_WINDOW; }
  catch (e) { return false; }
}

async function loginFailed(env, req, scope) {
  if (!env.DB) return;
  const key = `rl:${scope}:${clientIp(req)}`, now = Math.floor(Date.now() / 1000);
  let o = { n: 0, t0: now };
  try { const raw = await env.DB.get(key); if (raw) o = JSON.parse(raw); } catch (e) { /* nou */ }
  if (now - o.t0 >= LOGIN_WINDOW) o = { n: 0, t0: now };
  o.n += 1;
  await env.DB.put(key, JSON.stringify(o), { expirationTtl: LOGIN_WINDOW + 60 });
}

// ---------- semnatura raspunsurilor de licenta (Ed25519) ----------
// Cheia privata sta in secretul Cloudflare LICENSE_SIGN_KEY (pkcs8, base64). Botii au cheia
// publica si accepta "ok" doar cu semnatura valida pe: aurum1|hwid|product|status|expires|nonce|t
let SIGN_KEY = null;
async function signKey(env) {
  if (SIGN_KEY || !env.LICENSE_SIGN_KEY) return SIGN_KEY;
  const der = Uint8Array.from(atob(env.LICENSE_SIGN_KEY.trim()), c => c.charCodeAt(0));
  SIGN_KEY = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  return SIGN_KEY;
}

async function signLicense(env, res, hwid, product, nonce) {
  const key = await signKey(env);
  if (!key || !nonce) return res;
  const t = Math.floor(Date.now() / 1000);
  const msg = `aurum1|${hwid}|${product}|${res.status}|${Number(res.expires) || 0}|${nonce}|${t}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, enc.encode(msg)));
  return { ...res, t, sig: btoa(String.fromCharCode(...sig)) };
}

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json", ...headers },
  });
}

async function hmacHex(key, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function makeToken(secret) {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  return `${exp}.${await hmacHex(secret, String(exp))}`;
}

async function validToken(token, secret) {
  if (!token || !secret) return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const exp = token.slice(0, dot), sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Math.floor(Date.now() / 1000)) return false;
  return safeEq(sig, await hmacHex(secret, exp));
}

function getCookie(req, name) {
  const h = req.headers.get("Cookie") || "";
  for (const part of h.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return "";
}

function setCookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

// verifica un {password} din body fata de un secret; da cookie la potrivire
async function loginWith(request, secret, cookieName, env) {
  if (!secret) return json({ ok: false, error: "unconfigured" }, 500);
  if (env && await loginBlocked(env, request, cookieName))
    return json({ ok: false, error: "too many attempts, try again in 15 minutes" }, 429);
  let pw = "";
  try { const b = await request.json(); pw = (b && b.password) || ""; } catch (e) { pw = ""; }
  if (typeof pw === "string" && pw.length > 0 && safeEq(pw, secret)) {
    const tok = await makeToken(secret);
    return json({ ok: true }, 200, { "Set-Cookie": setCookie(cookieName, tok, MAX_AGE) });
  }
  if (env) await loginFailed(env, request, cookieName);
  return json({ ok: false, error: "bad" }, 401);
}

// validare minimala a bazei de unelte
function validTools(o) {
  return o && typeof o === "object" &&
    Array.isArray(o.cats) && Array.isArray(o.items) && Array.isArray(o.mats);
}

// ---------- licente (kill switch pentru unealta metin) ----------
// KV cheia "licenses": { updated_at, killAll:bool, list:[
//   { hwid, name, status:"active"|"blocked", expires:0|unixSec, note, added, last_seen } ] }
const LIC_EMPTY = { updated_at: 0, killAll: false, list: [] };

async function readLicenses(env) {
  if (!env.DB) return { ...LIC_EMPTY };
  const raw = await env.DB.get("licenses");
  if (!raw) return { ...LIC_EMPTY };
  try {
    const o = JSON.parse(raw);
    if (o && Array.isArray(o.list)) return o;
  } catch (e) { /* cade pe gol */ }
  return { ...LIC_EMPTY };
}

function validLicenses(o) {
  return o && typeof o === "object" && Array.isArray(o.list) &&
    o.list.every(e => e && typeof e.hwid === "string" && e.hwid.length > 0 &&
      (e.products === undefined || validProducts(e.products)));
}

function validProducts(p) {
  return p && typeof p === "object" && !Array.isArray(p) &&
    Object.entries(p).every(([k, v]) => PRODUCTS.includes(k) && Number.isFinite(Number(v)) && Number(v) >= 0);
}

// produse vandute: farm (Baerim Metin Queue), fishing (Pescar).
// Intrare noua: products = { farm: expires, fishing: expires } (0 = fara expirare;
// produs lipsa = fara acces). Intrarile vechi, fara "products", = doar farm cu e.expires.
const PRODUCTS = ["farm", "fishing"];

function entryProducts(e) {
  if (e.products && typeof e.products === "object") return e.products;
  return { farm: Number(e.expires) || 0 };
}

// decide statusul unui hwid pentru un produs: ok | killed | blocked | expired | noproduct | unknown
function licenseStatus(db, hwid, product = "farm") {
  if (db.killAll) return { status: "killed", message: "Access disabled by admin." };
  const e = (db.list || []).find(x => x.hwid === hwid);
  if (!e) return { status: "unknown", message: "This PC is not authorized. Send your ID to the admin." };
  if (e.status === "blocked") return { status: "blocked", message: "This PC has been blocked." };
  const prods = entryProducts(e);
  if (!Object.prototype.hasOwnProperty.call(prods, product))
    return { status: "noproduct", message: "This PC has no subscription for this bot." };
  const exp = Number(prods[product]) || 0;
  const now = Math.floor(Date.now() / 1000);
  if (exp > 0 && now > exp)
    return { status: "expired", message: "Your subscription has expired.", expires: exp };
  return { status: "ok", message: "", expires: exp, product };
}

// ---------- poarta "site in pregatire" ----------
// Cat timp site-ul nu e lansat, TOT site-ul cere parola de admin (ADMIN_PASSWORD).
// Raman deschise doar rutele de care au nevoie botii (licenta, publicare rapoarte)
// si cele de login. Lansare: variabila SITE_GATE = "off" in Cloudflare.
const GATE_OPEN = new Set([
  "/api/license", "/api/publish",
  "/api/admin/login", "/api/admin/logout", "/api/admin/me",
  "/favicon.ico", "/favicon-32.png", "/apple-touch-icon.png", "/og.png",
  "/discord",
]);

// aurumbots.com/discord -> invitatia pe serverul de Discord (fara expirare).
// Daca se schimba invitatia, se schimba doar aici; linkul public ramane acelasi.
const DISCORD_INVITE = "https://discord.gg/SxxWjZcJR3";

const GATE_HTML = `<!doctype html>
<html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Aurum — în curând</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<style>
:root{--bg:#080b16;--panel:#111a30;--line:#243256;--ink:#eaeefb;--mut:#9aa6c8;--gold:#e7b954;--gold2:#f6d488;--bad:#e2685f}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{display:grid;place-items:center;padding:16px;color:var(--ink);font-family:system-ui,"Segoe UI",sans-serif;
background:radial-gradient(1000px 520px at 78% -10%,rgba(231,185,84,.12),transparent 60%),radial-gradient(800px 460px at 8% 6%,rgba(90,120,255,.09),transparent 55%),var(--bg)}
.card{width:100%;max-width:380px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px 24px;box-shadow:0 18px 40px -20px rgba(0,0,0,.85)}
h1{margin:0 0 4px;font-size:22px;letter-spacing:.06em;color:var(--gold2)}
p{margin:0 0 20px;color:var(--mut);font-size:14px;line-height:1.5}
input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:#0b1020;color:var(--ink);font-size:15px}
input:focus{outline:2px solid var(--gold);outline-offset:1px}
button{margin-top:12px;width:100%;padding:12px;border:0;border-radius:10px;background:var(--gold);color:#1a1405;font-weight:700;font-size:15px;cursor:pointer}
button:disabled{opacity:.6;cursor:default}
.err{min-height:20px;margin-top:10px;color:var(--bad);font-size:13px}
</style></head><body>
<form class="card" id="f">
  <h1>AURUM</h1>
  <p>Site-ul este în pregătire și va fi disponibil în curând.</p>
  <input id="pw" type="password" autocomplete="current-password" placeholder="Parolă" aria-label="Parolă" required autofocus>
  <button id="b" type="submit">Intră</button>
  <div class="err" id="e" role="alert"></div>
</form>
<script>
document.getElementById("f").addEventListener("submit", async function (ev) {
  ev.preventDefault();
  var b = document.getElementById("b"), e = document.getElementById("e");
  b.disabled = true; e.textContent = "";
  try {
    var r = await fetch("/api/admin/login", {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: document.getElementById("pw").value})});
    if (r.ok) {
      // parola e buna; verificam ca browserul a pastrat cookie-ul de login
      var me = await fetch("/api/admin/me", {credentials: "same-origin", cache: "no-store"}).then(function (x) { return x.json(); });
      if (me && me.admin) { location.replace(location.pathname + location.search); return; }
      e.textContent = "Parola e corectă, dar browserul nu a păstrat cookie-ul de login. Permite cookie-urile pentru acest site (sau încearcă alt browser / o fereastră privată).";
      b.disabled = false; return;
    }
    e.textContent = r.status === 401 ? "Parolă greșită." : "Eroare pe server (" + r.status + "). Încearcă din nou.";
  } catch (x) { e.textContent = "Eroare de rețea, încearcă din nou."; }
  b.disabled = false;
});
</script>
</body></html>`;

function gatePage() {
  return new Response(GATE_HTML, {
    status: 401,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const site = env.SITE_PASSWORD;
    const admin = env.ADMIN_PASSWORD;

    if (p === "/discord" || p === "/discord/")
      return Response.redirect(DISCORD_INVITE, 302);

    if (env.SITE_GATE !== "off" && !GATE_OPEN.has(p) &&
        !await validToken(getCookie(request, ADM), admin)) {
      if (p.startsWith("/api/")) return json({ error: "site closed" }, 401);
      return gatePage();
    }

    // ---------- rapoarte (vizitator) ----------
    if (p === "/api/login" && request.method === "POST")
      return loginWith(request, site, SESS, env);
    if (p === "/api/logout" && request.method === "POST")
      return json({ ok: true }, 200, { "Set-Cookie": setCookie(SESS, "", 0) });

    if (p === "/api/publish" && request.method === "POST") {
      if (!site) return json({ ok: false, error: "unconfigured" }, 500);
      if (!safeEq(request.headers.get("X-Publish-Key") || "", site))
        return json({ ok: false, error: "bad key" }, 401);
      let text = "";
      try { text = await request.text(); } catch (e) { text = ""; }
      if (!text || text.length > 5_000_000) return json({ ok: false, error: "bad body" }, 400);
      try { JSON.parse(text); } catch (e) { return json({ ok: false, error: "not json" }, 400); }
      if (!env.DB) return json({ ok: false, error: "no kv" }, 500);
      await env.DB.put("latest", text);
      return json({ ok: true, saved: text.length });
    }

    if (p === "/api/reports") {
      if (!await validToken(getCookie(request, SESS), site))
        return json({ error: "unauthorized" }, 401);
      if (env.DB) { const raw = await env.DB.get("latest"); if (raw)
        return new Response(raw, { headers: { "Content-Type": "application/json" } }); }
      return json(DEMO);
    }

    // ---------- admin ----------
    if (p === "/api/admin/login" && request.method === "POST")
      return loginWith(request, admin, ADM, env);
    if (p === "/api/admin/logout" && request.method === "POST")
      return json({ ok: true }, 200, { "Set-Cookie": setCookie(ADM, "", 0) });
    if (p === "/api/admin/me")
      return json({ admin: await validToken(getCookie(request, ADM), admin) });

    // ---------- unelte (tools DB) ----------
    if (p === "/api/tools" && request.method === "GET") {
      if (env.DB) { const raw = await env.DB.get("tools_db"); if (raw)
        return new Response(raw, { headers: { "Content-Type": "application/json" } }); }
      return json(DEFAULT_TOOLS);
    }
    if (p === "/api/tools" && request.method === "POST") {
      if (!await validToken(getCookie(request, ADM), admin))
        return json({ ok: false, error: "unauthorized" }, 401);
      let text = "";
      try { text = await request.text(); } catch (e) { text = ""; }
      if (!text || text.length > 2_000_000) return json({ ok: false, error: "bad body" }, 400);
      let obj;
      try { obj = JSON.parse(text); } catch (e) { return json({ ok: false, error: "not json" }, 400); }
      if (!validTools(obj)) return json({ ok: false, error: "bad shape" }, 400);
      obj.updated_at = Math.floor(Date.now() / 1000);
      if (!env.DB) return json({ ok: false, error: "no kv" }, 500);
      await env.DB.put("tools_db", JSON.stringify(obj));
      return json({ ok: true, updated_at: obj.updated_at });
    }

    // ---------- licente ----------
    // verificarea facuta de unealta (publica): raspunde ok/blocked/... pt un hwid
    if (p === "/api/license" && request.method === "GET") {
      const hwid = (url.searchParams.get("hwid") || "").trim().slice(0, 128);
      if (!hwid) return json({ status: "unknown", message: "no id" });
      // botii vechi nu trimit ?product -> farm
      const product = (url.searchParams.get("product") || "farm").trim();
      if (!PRODUCTS.includes(product)) return json({ status: "unknown", message: "bad product" });
      const db = await readLicenses(env);
      // fara trial: un PC primeste acces doar cand e adaugat din licente.html
      const nonce = (url.searchParams.get("n") || "").trim().slice(0, 64);
      const res = licenseStatus(db, hwid, product);
      // marcheaza "last_seen" (o data pe ora max, ca sa nu scrie KV la fiecare pornire)
      if (env.DB) {
        const e = (db.list || []).find(x => x.hwid === hwid);
        const now = Math.floor(Date.now() / 1000);
        if (e && (!e.last_seen || now - Number(e.last_seen) > 3600)) {
          e.last_seen = now;
          try { await env.DB.put("licenses", JSON.stringify(db)); } catch (err) { /* ignora */ }
        }
      }
      return json(await signLicense(env, res, hwid, product, nonce), 200, { "Cache-Control": "no-store" });
    }
    // admin: citeste toata lista
    if (p === "/api/admin/licenses" && request.method === "GET") {
      if (!await validToken(getCookie(request, ADM), admin))
        return json({ ok: false, error: "unauthorized" }, 401);
      return json(await readLicenses(env));
    }
    // admin: salveaza toata lista (kill / add / edit din pagina de admin)
    if (p === "/api/admin/licenses" && request.method === "POST") {
      if (!await validToken(getCookie(request, ADM), admin))
        return json({ ok: false, error: "unauthorized" }, 401);
      let text = "";
      try { text = await request.text(); } catch (e) { text = ""; }
      if (!text || text.length > 1_000_000) return json({ ok: false, error: "bad body" }, 400);
      let obj;
      try { obj = JSON.parse(text); } catch (e) { return json({ ok: false, error: "not json" }, 400); }
      if (!validLicenses(obj)) return json({ ok: false, error: "bad shape" }, 400);
      obj.killAll = !!obj.killAll;
      delete obj.trialHours;                       // trialul a fost scos complet
      obj.updated_at = Math.floor(Date.now() / 1000);
      if (!env.DB) return json({ ok: false, error: "no kv" }, 500);
      await env.DB.put("licenses", JSON.stringify(obj));
      return json({ ok: true, updated_at: obj.updated_at, count: obj.list.length });
    }

    // orice altceva -> fisierele statice
    return env.ASSETS.fetch(request);
  },
};
