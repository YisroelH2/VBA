import { createSessionCookie } from "../../_lib/session.js";

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i === -1) return;
    out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

// Decodes the id_token payload without verifying its signature. That's safe
// here specifically because we received this token directly from Google's
// token endpoint over a server-to-server HTTPS call we made ourselves (the
// authorization-code flow) — not from the browser, where it could be forged.
function decodeJwtPayload(jwt) {
  const payloadB64 = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(payloadB64));
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const fail = (msg) => Response.redirect(`${url.origin}/?authError=${encodeURIComponent(msg)}`, 302);

  const error = url.searchParams.get("error");
  if (error) return fail(error);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return fail("Missing authorization code");

  const cookies = parseCookies(request.headers.get("Cookie"));
  if (!cookies.vba_oauth_state || cookies.vba_oauth_state !== state) {
    return fail("Sign-in session expired — please try again");
  }

  const redirectUri = `${url.origin}/api/auth/google-callback`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenRes.ok) return fail("Google sign-in failed");
  const tokens = await tokenRes.json();
  if (!tokens.id_token) return fail("Google sign-in failed");

  const claims = decodeJwtPayload(tokens.id_token);
  const ownerEmail = (env.OWNER_EMAIL || "").trim().toLowerCase();
  if (!ownerEmail || !claims.email || !claims.email_verified || claims.email.toLowerCase() !== ownerEmail) {
    return fail("That Google account isn't authorized for this app");
  }

  const headers = new Headers({ Location: `${url.origin}/?signedIn=1` });
  headers.append("Set-Cookie", await createSessionCookie(env.SESSION_SECRET));
  headers.append("Set-Cookie", "vba_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  return new Response(null, { status: 302, headers });
}
