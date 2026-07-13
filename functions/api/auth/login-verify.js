import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { USER_ID, createSessionCookie } from "../../_lib/session.js";
import { rpConfig, consumeChallenge } from "../../_lib/webauthn-config.js";

export async function onRequestPost({ request, env }) {
  const { rpID, origin } = rpConfig(request);
  const { response, challengeId } = await request.json();

  const expectedChallenge = await consumeChallenge(env.DB, challengeId, "login");
  if (!expectedChallenge) {
    return new Response(JSON.stringify({ verified: false, error: "Challenge expired or invalid" }), { status: 400 });
  }

  const authenticator = await env.DB.prepare(
    "SELECT * FROM authenticators WHERE credential_id = ? AND user_id = ?"
  ).bind(response.id, USER_ID).first();
  if (!authenticator) {
    return new Response(JSON.stringify({ verified: false, error: "Unknown credential" }), { status: 400 });
  }

  const publicKey = Uint8Array.from(atob(authenticator.public_key), c => c.charCodeAt(0));

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: authenticator.credential_id,
        publicKey,
        counter: authenticator.counter,
      },
    });
  } catch (e) {
    return new Response(JSON.stringify({ verified: false, error: e.message }), { status: 400 });
  }

  if (!verification.verified) {
    return new Response(JSON.stringify({ verified: false }), { status: 400 });
  }

  await env.DB.prepare("UPDATE authenticators SET counter = ? WHERE credential_id = ?")
    .bind(verification.authenticationInfo.newCounter, authenticator.credential_id).run();

  const cookie = await createSessionCookie(env.SESSION_SECRET);
  return new Response(JSON.stringify({ verified: true }), {
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie },
  });
}
