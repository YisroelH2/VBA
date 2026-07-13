import { verifySession } from "../../_lib/session.js";

async function requireAuth(request, env) {
  const session = await verifySession(request, env.SESSION_SECRET);
  return !!session;
}

export async function onRequestGet({ request, env }) {
  if (!(await requireAuth(request, env))) {
    return new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 });
  }

  const [meta, transactions, investments, loans, pending] = await Promise.all([
    env.DB.prepare("SELECT * FROM meta WHERE id = 1").first(),
    env.DB.prepare("SELECT * FROM transactions ORDER BY id DESC").all(),
    env.DB.prepare("SELECT data FROM investments").all(),
    env.DB.prepare("SELECT data FROM loans").all(),
    env.DB.prepare("SELECT data FROM pending").all(),
  ]);

  const state = {
    balance: meta ? meta.balance : 0,
    maaserOwed: meta ? meta.maaser_owed : 0,
    maaserEverPaid: meta ? !!meta.maaser_ever_paid : false,
    updatedAt: meta ? Number(meta.updated_at) || 0 : 0,
    transactions: transactions.results.map(t => ({
      id: t.id, type: t.type, desc: t.desc, amount: t.amount, delta: t.delta,
      date: t.date, balance: t.balance_after, maaser: !!t.maaser, maaserAmt: t.maaser_amt,
    })),
    investments: investments.results.map(r => JSON.parse(r.data)),
    loans: loans.results.map(r => JSON.parse(r.data)),
    pending: pending.results.map(r => JSON.parse(r.data)),
  };

  return new Response(JSON.stringify(state), { headers: { "Content-Type": "application/json" } });
}

export async function onRequestPost({ request, env }) {
  if (!(await requireAuth(request, env))) {
    return new Response(JSON.stringify({ error: "Not authenticated" }), { status: 401 });
  }

  const state = await request.json();
  if (!state || !Array.isArray(state.transactions)) {
    return new Response(JSON.stringify({ error: "Malformed state" }), { status: 400 });
  }

  const updatedAt = Date.now();
  const stmts = [
    env.DB.prepare(
      "UPDATE meta SET balance = ?, maaser_owed = ?, maaser_ever_paid = ?, updated_at = ? WHERE id = 1"
    ).bind(state.balance || 0, state.maaserOwed || 0, state.maaserEverPaid ? 1 : 0, updatedAt),
    env.DB.prepare("DELETE FROM transactions"),
    env.DB.prepare("DELETE FROM investments"),
    env.DB.prepare("DELETE FROM loans"),
    env.DB.prepare("DELETE FROM pending"),
  ];

  for (const t of state.transactions) {
    stmts.push(env.DB.prepare(
      `INSERT INTO transactions (id, type, desc, amount, delta, date, balance_after, maaser, maaser_amt, synced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(t.id, t.type, t.desc, t.amount, t.delta, t.date, t.balance, t.maaser ? 1 : 0, t.maaserAmt || 0));
  }
  for (const inv of (state.investments || [])) {
    stmts.push(env.DB.prepare(
      "INSERT INTO investments (id, data, synced_at) VALUES (?, ?, datetime('now'))"
    ).bind(inv.id, JSON.stringify(inv)));
  }
  for (const loan of (state.loans || [])) {
    stmts.push(env.DB.prepare(
      "INSERT INTO loans (id, data, synced_at) VALUES (?, ?, datetime('now'))"
    ).bind(loan.id, JSON.stringify(loan)));
  }
  for (const p of (state.pending || [])) {
    stmts.push(env.DB.prepare(
      "INSERT INTO pending (id, data, synced_at) VALUES (?, ?, datetime('now'))"
    ).bind(p.id, JSON.stringify(p)));
  }

  await env.DB.batch(stmts);

  return new Response(JSON.stringify({ synced: true, updatedAt }), { headers: { "Content-Type": "application/json" } });
}
