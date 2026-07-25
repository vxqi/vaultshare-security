const db = require('../db');
const activityLog = require('../utils/activityLog');

// Simplified plan model for coursework scope: a one-time "upgrade" purchase
// rather than real recurring billing. No payment card details are ever
// collected or stored by this app - a production deployment would hand off
// to a PCI-compliant processor (e.g. Stripe Checkout) and only ever receive
// a webhook confirmation back, never raw card data. This table and flow
// model the internal side: what the user was charged and what it bought them.
const PLANS = {
  free: { label: 'Free', storageLimitMb: 500, priceCents: 0 },
  pro: { label: 'Pro', storageLimitMb: 5000, priceCents: 500 }, // $5.00
};

function getUsageMb(userId) {
  const row = db.prepare(
    `SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files WHERE owner_id = ? AND deleted_at IS NULL`
  ).get(userId);
  return row.total / (1024 * 1024);
}

async function showBilling(req, res) {
  const user = db.prepare('SELECT id, plan, storage_limit_mb FROM users WHERE id = ?').get(req.session.userId);
  const usageMb = getUsageMb(req.session.userId);
  const transactions = db.prepare(
    'SELECT type, amount_cents, currency, status, description, created_at FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(req.session.userId);

  res.render('billing/index', {
    title: 'Billing', user, usageMb, transactions, plans: PLANS, error: null, activeNav: 'billing', query: req.query,
  });
}

// Wrapped in a single atomic DB transaction: the ledger entry and the plan
// change either both happen or neither does. If anything throws partway
// through, better-sqlite3's db.transaction() automatically rolls back
// everything written so far in this call - there is no way to end up with a
// transaction row recorded but the plan not actually changed, or vice versa.
const performUpgrade = db.transaction((userId) => {
  const plan = PLANS.pro;
  db.prepare(
    `INSERT INTO transactions (user_id, type, amount_cents, currency, status, description) VALUES (?, 'upgrade', ?, 'USD', 'completed', ?)`
  ).run(userId, plan.priceCents, `Upgrade to ${plan.label} (${plan.storageLimitMb} MB storage)`);

  const info = db.prepare(`UPDATE users SET plan = 'pro', storage_limit_mb = ? WHERE id = ? AND plan = 'free'`)
    .run(plan.storageLimitMb, userId);

  // If the row wasn't actually updated (e.g. a concurrent request already
  // upgraded this account), throw to roll back the transaction row we just
  // inserted too - we never want a "charge" recorded with no matching effect.
  if (info.changes === 0) {
    throw new Error('Account is not currently on the free plan.');
  }
});

async function upgrade(req, res) {
  const user = db.prepare('SELECT id, plan FROM users WHERE id = ?').get(req.session.userId);

  if (user.plan !== 'free') {
    return res.status(400).render('errors/403', { title: 'Already upgraded', message: 'Your account is already on the Pro plan.' });
  }

  try {
    performUpgrade(req.session.userId);
  } catch (err) {
    activityLog.log({ userId: req.session.userId, action: 'billing_upgrade_failed', req, metadata: { reason: err.message } });
    return res.status(409).render('errors/403', { title: 'Upgrade failed', message: 'This account could not be upgraded. Please try again.' });
  }

  activityLog.log({ userId: req.session.userId, action: 'billing_upgrade', req, metadata: { amountCents: PLANS.pro.priceCents } });
  res.redirect('/billing?upgraded=1');
}

const performDowngrade = db.transaction((userId) => {
  db.prepare(
    `INSERT INTO transactions (user_id, type, amount_cents, currency, status, description) VALUES (?, 'downgrade', 0, 'USD', 'completed', ?)`
  ).run(userId, `Downgrade to ${PLANS.free.label} (${PLANS.free.storageLimitMb} MB storage)`);

  const info = db.prepare(`UPDATE users SET plan = 'free', storage_limit_mb = ? WHERE id = ? AND plan = 'pro'`)
    .run(PLANS.free.storageLimitMb, userId);

  if (info.changes === 0) {
    throw new Error('Account is not currently on the pro plan.');
  }
});

async function downgrade(req, res) {
  const user = db.prepare('SELECT id, plan FROM users WHERE id = ?').get(req.session.userId);

  if (user.plan !== 'pro') {
    return res.status(400).render('errors/403', { title: 'Not on Pro', message: 'Your account is not currently on the Pro plan.' });
  }

  const usageMb = getUsageMb(req.session.userId);
  if (usageMb > PLANS.free.storageLimitMb) {
    return res.status(400).render('errors/403', {
      title: 'Cannot downgrade',
      message: `You're using ${usageMb.toFixed(1)} MB, which is over the Free plan's ${PLANS.free.storageLimitMb} MB limit. Delete some files first.`,
    });
  }

  try {
    performDowngrade(req.session.userId);
  } catch (err) {
    activityLog.log({ userId: req.session.userId, action: 'billing_downgrade_failed', req, metadata: { reason: err.message } });
    return res.status(409).render('errors/403', { title: 'Downgrade failed', message: 'This account could not be downgraded. Please try again.' });
  }

  activityLog.log({ userId: req.session.userId, action: 'billing_downgrade', req });
  res.redirect('/billing?downgraded=1');
}

module.exports = { showBilling, upgrade, downgrade, getUsageMb, PLANS };