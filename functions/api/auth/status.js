import { USER_ID, verifySession } from "../../_lib/session.js";

export async function onRequestGet({ request, env }) {
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM authenticators WHERE user_id = ?"
  ).bind(USER_ID).first();
  const session = await verifySession(request, env.SESSION_SECRET);

  return new Response(JSON.stringify({
    hasCredential: count.n > 0,
    authenticated: !!session,
  }), { headers: { "Content-Type": "application/json" } });
}
