// Worker deliricbae: servește site-ul static (ASSETS) și protejează /api/reports
// cu o parolă verificată PE SERVER. Parola se ține ca secret in Cloudflare
// (SITE_PASSWORD) — nu apare niciodata in cod sau in pagina.
//
// Datele raportului stau in Cloudflare KV (binding REPORTS, cheia "latest").
// Publisher-ul de pe PC le trimite prin POST /api/publish, autentificat cu
// acelasi SITE_PASSWORD (header X-Publish-Key). /api/reports (GET) le citeste,
// dupa ce verifica sesiunea (cookie semnat HMAC).

const COOKIE = "dbsess";
const MAX_AGE = 7 * 24 * 3600;           // 7 zile
const enc = new TextEncoder();

// fallback afisat DOAR pana la prima publicare reala (KV gol)
const DEMO = {
  generated_at: 0, player: "",
  totals: { sessions: 0, yang: 0, kills: 0, seconds: 0, loot_value: 0 },
  daily: [], top_loot: [], days: [], empty: true,
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

// comparatie in timp constant (nu scurge lungimea potrivirii)
function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function makeToken(secret) {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const sig = await hmacHex(secret, String(exp));
  return `${exp}.${sig}`;
}

async function validToken(token, secret) {
  if (!token || !secret) return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const exp = token.slice(0, dot), sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Math.floor(Date.now() / 1000)) return false;
  const want = await hmacHex(secret, exp);
  return safeEq(sig, want);
}

function getCookie(req, name) {
  const h = req.headers.get("Cookie") || "";
  for (const part of h.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return "";
}

function setCookie(value, maxAge) {
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const secret = env.SITE_PASSWORD;

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!secret) return json({ ok: false, error: "unconfigured" }, 500);
      let pw = "";
      try {
        const b = await request.json();
        pw = (b && b.password) || "";
      } catch (e) { pw = ""; }
      if (typeof pw === "string" && pw.length > 0 && safeEq(pw, secret)) {
        const tok = await makeToken(secret);
        return json({ ok: true }, 200, { "Set-Cookie": setCookie(tok, MAX_AGE) });
      }
      return json({ ok: false, error: "bad" }, 401);
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      return json({ ok: true }, 200, { "Set-Cookie": setCookie("", 0) });
    }

    // ---- publicare date din publisher-ul de pe PC ----
    if (url.pathname === "/api/publish" && request.method === "POST") {
      if (!secret) return json({ ok: false, error: "unconfigured" }, 500);
      const key = request.headers.get("X-Publish-Key") || "";
      if (!safeEq(key, secret)) return json({ ok: false, error: "bad key" }, 401);
      let text = "";
      try { text = await request.text(); } catch (e) { text = ""; }
      if (!text || text.length > 5_000_000) return json({ ok: false, error: "bad body" }, 400);
      try { JSON.parse(text); } catch (e) { return json({ ok: false, error: "not json" }, 400); }
      if (!env.REPORTS) return json({ ok: false, error: "no kv" }, 500);
      await env.REPORTS.put("latest", text);
      return json({ ok: true, saved: text.length });
    }

    if (url.pathname === "/api/reports") {
      const ok = await validToken(getCookie(request, COOKIE), secret);
      if (!ok) return json({ error: "unauthorized" }, 401);
      if (env.REPORTS) {
        const raw = await env.REPORTS.get("latest");
        if (raw) return new Response(raw, { headers: { "Content-Type": "application/json" } });
      }
      return json(DEMO);
    }

    // orice altceva -> fisierele statice (shell-ul, fonturile locale etc.)
    return env.ASSETS.fetch(request);
  },
};
