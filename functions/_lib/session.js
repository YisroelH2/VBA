// Minimal HMAC-signed session cookie (single-user app: no user table beyond "default").
const USER_ID = "default";
const COOKIE_NAME = "vba_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function createSessionCookie(secret) {
  const payload = JSON.stringify({ uid: USER_ID, exp: Date.now() + SESSION_TTL_MS });
  const payloadB64 = b64url(new TextEncoder().encode(payload));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  const token = `${payloadB64}.${b64url(sig)}`;
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`;
}

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i === -1) return;
    out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

async function verifySession(request, secret) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) return null;
  const key = await hmacKey(secret);
  const valid = await crypto.subtle.verify("HMAC", key, b64urlDecode(sigB64), new TextEncoder().encode(payloadB64));
  if (!valid) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

async function requireAuth(request, env) {
  const session = await verifySession(request, env.SESSION_SECRET);
  return !!session;
}

export { USER_ID, createSessionCookie, verifySession, requireAuth };
