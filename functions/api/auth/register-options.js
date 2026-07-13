import { generateRegistrationOptions } from "@simplewebauthn/server";
import { USER_ID } from "../../_lib/session.js";
import { rpConfig, saveChallenge } from "../../_lib/webauthn-config.js";

export async function onRequestGet({ request, env }) {
  const { rpID, rpName } = rpConfig(request);

  const existing = await env.DB.prepare(
    "SELECT credential_id FROM authenticators WHERE user_id = ?"
  ).bind(USER_ID).all();

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: "VBA User",
    userID: new TextEncoder().encode(USER_ID),
    attestationType: "none",
    excludeCredentials: existing.results.map(r => ({ id: r.credential_id })),
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
  });

  const challengeId = await saveChallenge(env.DB, USER_ID, "register", options.challenge);

  return new Response(JSON.stringify({ options, challengeId }), {
    headers: { "Content-Type": "application/json" },
  });
}
