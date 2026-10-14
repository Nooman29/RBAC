// Drop-in client for the DSFS central auth service (Node 18+, uses built-in fetch).
//
//   const { requirePermission } = require('./dsfsAuth');
//   app.get('/schools/:schoolId/attendance',
//     requirePermission('attendance', 'read', req => ({ school_id: req.params.schoolId })),
//     (req, res) => res.json({ userId: req.auth.user_id }));
//
// Environment: DSFS_AUTH_URL, DSFS_CLIENT_ID, DSFS_CLIENT_SECRET

const BASE = (process.env.DSFS_AUTH_URL || 'http://localhost:8000').replace(/\/$/, '');

async function post(path, body) {
  const res = await fetch(`${BASE}/api/v1${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': process.env.DSFS_CLIENT_ID,
      'X-Client-Secret': process.env.DSFS_CLIENT_SECRET,
    },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

// Returns { active, user_id, roles, permissions, ... } (active:false when the token is not valid).
async function introspect(token) {
  const { status, data } = await post('/auth/introspect', { token });
  if (status !== 200) throw new Error(`introspect failed: ${status} ${JSON.stringify(data)}`);
  return data;
}

// Returns { allowed, reason, user_id, roles }.
async function check(token, resource, action, context = {}) {
  const { status, data } = await post('/authz/check', { token, resource, action, context });
  if (status === 200) return data;
  if (status === 401 && data.error && data.error.code === 'token_inactive') {
    return { allowed: false, reason: 'token_inactive', user_id: null, roles: [] };
  }
  throw new Error(`authz check failed: ${status} ${JSON.stringify(data)}`);
}

// Express middleware factory. contextFn(req) -> context object (school_id, student_id, ...).
function requirePermission(resource, action, contextFn) {
  return async (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.toLowerCase().startsWith('bearer ')) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }
    try {
      const decision = await check(header.slice(7).trim(), resource, action, contextFn ? contextFn(req) : {});
      if (!decision.allowed) {
        const status = decision.reason === 'token_inactive' ? 401 : 403;
        return res.status(status).json({ error: `Access denied: ${decision.reason}` });
      }
      req.auth = decision;
      return next();
    } catch (err) {
      return res.status(503).json({ error: err.message });
    }
  };
}

module.exports = { introspect, check, requirePermission };