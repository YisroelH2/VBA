import { COOKIE_NAME } from "../../_lib/session.js";

export async function onRequestPost() {
  const headers = new Headers({ "Content-Type": "application/json" });
  headers.append("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  return new Response(JSON.stringify({ ok: true }), { headers });
}
