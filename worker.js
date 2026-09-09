// Worker deliricbae: servește site-ul static (ASSETS) și protejează /api/reports
// cu o parolă verificată PE SERVER. Parola se ține ca secret in Cloudflare
// (SITE_PASSWORD) — nu apare niciodata in cod sau in pagina.

const COOKIE = "dbsess";
const MAX_AGE = 7 * 24 * 3600;           // 7 zile
const enc = new TextEncoder();

// --- date raport (deocamdata demo; maine le inlocuim cu sessions.json real) ---
const REPORTS = {
  daily: [{d:"31.08",k:640},{d:"01.09",k:912},{d:"02.09",k:0},{d:"03.09",k:1180},
    {d:"04.09",k:1044},{d:"05.09",k:760},{d:"06.09",k:1320},{d:"07.09",k:1190},
    {d:"08.09",k:1190},{d:"09.09",k:903}],
  allTime: 41316,
  days: [
    {date:"09.09.2026",wd:"Marți",sessions:[
      {t:"20:41",dur:78,L:150,R:111,types:[150,80,24,7],aura:3,berserk:2,mg:[12,0,1]},
      {t:"22:10",dur:205,L:360,R:282,types:[360,190,70,22],aura:8,berserk:6,mg:[33,1,2]}]},
    {date:"08.09.2026",wd:"Luni",sessions:[
      {t:"19:02",dur:320,L:520,R:460,types:[520,300,120,40],aura:12,berserk:10,mg:[40,2,1]},
      {t:"23:48",dur:70,L:118,R:92,types:[118,66,20,6],aura:2,berserk:2,mg:[9,0,1]}]},
    {date:"07.09.2026",wd:"Duminică",sessions:[
      {t:"18:15",dur:410,L:640,R:540,types:[640,360,140,50],aura:15,berserk:13,mg:[52,3,2]},
      {t:"01:20",dur:95,L:150,R:110,types:[150,72,30,8],aura:3,berserk:3,mg:[11,1,0]}]},
  ]};

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
  if (a.length !== b.length) return false;
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

    if (url.pathname === "/api/reports") {
      const ok = await validToken(getCookie(request, COOKIE), secret);
      if (!ok) return json({ error: "unauthorized" }, 401);
      return json(REPORTS);
    }

    // orice altceva -> fisierele statice (shell-ul, fonturile locale etc.)
    return env.ASSETS.fetch(request);
  },
};
