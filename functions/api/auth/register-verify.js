import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { USER_ID, createSessionCookie, requireAuth } from "../../_lib/session.js";
import { rpConfig, consumeChallenge } from "../../_lib/webauthn-config.js";

export async function onRequestPost({ request, env }) {
  const { rpID, origin } = rpConfig(request);
  const { response, challengeId, deviceName } = await request.json();

  const existingCount = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM authenticators WHERE user_id = ?"
  ).bind(USER_ID).first();
  if (existingCount.n > 0 && !(await requireAuth(request, env))) {
    return new Response(JSON.stringify({ verified: false, error: "Sign in first to register a new device" }), { status: 401 });
  }

  const expectedChallenge = await consumeChallenge(env.DB, challengeId, "register");
  if (!expectedChallenge) {
    return new Response(JSON.stringify({ verified: false, error: "Challenge expired or invalid" }), { status: 400 });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (e) {
    return new Response(JSON.stringify({ verified: false, error: e.message }), { status: 400 });
  }

  if (!verification.verified || !verification.registrationInfo) {
    return new Response(JSON.stringify({ verified: false }), { status: 400 });
  }

  const { credential } = verification.registrationInfo;
  await env.DB.prepare(
    "INSERT INTO authenticators (credential_id, public_key, user_id, counter, device_name) VALUES (?, ?, ?, ?, ?)"
  ).bind(
    credential.id,
    btoa(String.fromCharCode(...credential.publicKey)),
    USER_ID,
    credential.counter,
    deviceName || null
  ).run();

  const cookie = await createSessionCookie(env.SESSION_SECRET);
  return new Response(JSON.stringify({ verified: true }), {
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie },
  });
}
