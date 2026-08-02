import { verifySession } from "../../_lib/session.js";

export async function onRequestGet({ request, env }) {
  const session = await verifySession(request, env.SESSION_SECRET);
  return new Response(JSON.stringify({ authenticated: !!session }), {
    headers: { "Content-Type": "application/json" },
  });
}
