import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { USER_ID } from "../../_lib/session.js";
import { rpConfig, saveChallenge } from "../../_lib/webauthn-config.js";

export async function onRequestGet({ request, env }) {
  const { rpID } = rpConfig(request);

  const existing = await env.DB.prepare(
    "SELECT credential_id FROM authenticators WHERE user_id = ?"
  ).bind(USER_ID).all();

  if (existing.results.length === 0) {
    return new Response(JSON.stringify({ error: "No credentials registered" }), { status: 404 });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: existing.results.map(r => ({ id: r.credential_id })),
    userVerification: "required",
  });

  const challengeId = await saveChallenge(env.DB, USER_ID, "login", options.challenge);

  return new Response(JSON.stringify({ options, challengeId }), {
    headers: { "Content-Type": "application/json" },
  });
}
