// Worker deliricbae.
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
async function loginWith(request, secret, cookieName) {
  if (!secret) return json({ ok: false, error: "unconfigured" }, 500);
  let pw = "";
  try { const b = await request.json(); pw = (b && b.password) || ""; } catch (e) { pw = ""; }
  if (typeof pw === "string" && pw.length > 0 && safeEq(pw, secret)) {
    const tok = await makeToken(secret);
    return json({ ok: true }, 200, { "Set-Cookie": setCookie(cookieName, tok, MAX_AGE) });
  }
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
    o.list.every(e => e && typeof e.hwid === "string" && e.hwid.length > 0);
}

// decide statusul unui hwid: ok | killed | blocked | expired | unknown
function licenseStatus(db, hwid) {
  if (db.killAll) return { status: "killed", message: "Access disabled by admin." };
  const e = (db.list || []).find(x => x.hwid === hwid);
  if (!e) return { status: "unknown", message: "This PC is not authorized. Send your ID to the admin." };
  if (e.status === "blocked") return { status: "blocked", message: "This PC has been blocked.", name: e.name || "" };
  const now = Math.floor(Date.now() / 1000);
  if (e.expires && Number(e.expires) > 0 && now > Number(e.expires))
    return { status: "expired", message: "Your access has expired.", name: e.name || "", expires: e.expires };
  return { status: "ok", message: "", name: e.name || "", expires: e.expires || 0 };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const site = env.SITE_PASSWORD;
    const admin = env.ADMIN_PASSWORD;

    // ---------- rapoarte (vizitator) ----------
    if (p === "/api/login" && request.method === "POST")
      return loginWith(request, site, SESS);
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
      return loginWith(request, admin, ADM);
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
      const db = await readLicenses(env);
      const res = licenseStatus(db, hwid);
      // marcheaza "last_seen" (o data pe ora max, ca sa nu scrie KV la fiecare pornire)
      if (env.DB) {
        const e = (db.list || []).find(x => x.hwid === hwid);
        const now = Math.floor(Date.now() / 1000);
        if (e && (!e.last_seen || now - Number(e.last_seen) > 3600)) {
          e.last_seen = now;
          try { await env.DB.put("licenses", JSON.stringify(db)); } catch (err) { /* ignora */ }
        }
      }
      return json(res, 200, { "Cache-Control": "no-store" });
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
      obj.updated_at = Math.floor(Date.now() / 1000);
      if (!env.DB) return json({ ok: false, error: "no kv" }, 500);
      await env.DB.put("licenses", JSON.stringify(obj));
      return json({ ok: true, updated_at: obj.updated_at, count: obj.list.length });
    }

    // orice altceva -> fisierele statice
    return env.ASSETS.fetch(request);
  },
};
