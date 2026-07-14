import { createSessionCookie } from "../../_lib/session.js";

const MAX_FAILS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time comparison of two equal-length hex digests.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  if (!env.AUTH_PASSWORD) {
    return new Response(JSON.stringify({ error: "Password sign-in isn't configured" }), { status: 503 });
  }

  const row = await env.DB.prepare("SELECT * FROM login_attempts WHERE id = 1").first();
  const now = Date.now();
  if (row && row.locked_until > now) {
    return new Response(
      JSON.stringify({ error: "Too many failed attempts. Try again later.", lockedUntil: row.locked_until }),
      { status: 429 }
    );
  }

  const { password } = await request.json().catch(() => ({}));
  const match = typeof password === "string" &&
    timingSafeEqual(await sha256Hex(password), await sha256Hex(env.AUTH_PASSWORD));

  if (!match) {
    const failCount = (row ? row.fail_count : 0) + 1;
    const lockedUntil = failCount >= MAX_FAILS ? now + LOCKOUT_MS : 0;
    await env.DB.prepare(
      "INSERT INTO login_attempts (id, fail_count, locked_until) VALUES (1, ?, ?) " +
      "ON CONFLICT(id) DO UPDATE SET fail_count = ?, locked_until = ?"
    ).bind(failCount % MAX_FAILS, lockedUntil, failCount % MAX_FAILS, lockedUntil).run();
    return new Response(JSON.stringify({ error: "Incorrect password" }), { status: 401 });
  }

  await env.DB.prepare(
    "INSERT INTO login_attempts (id, fail_count, locked_until) VALUES (1, 0, 0) " +
    "ON CONFLICT(id) DO UPDATE SET fail_count = 0, locked_until = 0"
  ).run();

  const cookie = await createSessionCookie(env.SESSION_SECRET);
  return new Response(JSON.stringify({ verified: true }), {
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie },
  });
}
