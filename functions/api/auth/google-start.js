export async function onRequestGet({ request, env }) {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response("Google sign-in isn't configured yet", { status: 503 });
  }

  const url = new URL(request.url);
  const redirectUri = `${url.origin}/api/auth/google-callback`;
  const state = crypto.randomUUID();

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid email");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("prompt", "select_account");

  const headers = new Headers({ Location: authUrl.toString() });
  headers.append("Set-Cookie", `vba_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);
  return new Response(null, { status: 302, headers });
}
