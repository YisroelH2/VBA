// Derives rpID/origin from the incoming request so this works unmodified
// across localhost dev, *.pages.dev previews, and a future custom domain.
function rpConfig(request) {
  const url = new URL(request.url);
  return { rpID: url.hostname, origin: url.origin, rpName: "Virtual Bank Account" };
}

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

async function saveChallenge(db, userId, type, challenge) {
  const id = crypto.randomUUID();
  await db.prepare(
    "INSERT INTO auth_challenges (id, challenge, user_id, type, expires_at) VALUES (?, ?, ?, ?, ?)"
  ).bind(id, challenge, userId, type, Date.now() + CHALLENGE_TTL_MS).run();
  return id;
}

async function consumeChallenge(db, id, type) {
  const row = await db.prepare(
    "SELECT * FROM auth_challenges WHERE id = ? AND type = ?"
  ).bind(id, type).first();
  if (!row) return null;
  await db.prepare("DELETE FROM auth_challenges WHERE id = ?").bind(id).run();
  if (row.expires_at < Date.now()) return null;
  return row.challenge;
}

export { rpConfig, saveChallenge, consumeChallenge };
