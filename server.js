import { createServer } from 'node:http'

// --- Config (env vars) ---
const PORT = parseInt(process.env.PORT || '3000', 10)
const SUPABASE_URL = process.env.SUPABASE_URL || ''
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || ''
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',')

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing required env vars: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY')
  process.exit(1)
}

// --- CORS ---
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)
  return {
    'Access-Control-Allow-Origin': allowed ? (origin || '*') : '',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  }
}

// --- Helpers ---
function jsonResponse(res, status, body, origin) {
  const headers = { ...corsHeaders(origin), 'Content-Type': 'application/json' }
  res.writeHead(status, headers)
  res.end(JSON.stringify(body))
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString()))
    req.on('error', reject)
  })
}

// --- Routes ---

/**
 * POST /auth/token
 * Body: { email, password }
 * → Forwards to Supabase Auth, returns { access_token, expires_in, user }
 */
async function handleAuthToken(req, res, origin) {
  const raw = await readBody(req)
  let body
  try {
    body = JSON.parse(raw)
  } catch {
    return jsonResponse(res, 400, { error: 'Invalid JSON' }, origin)
  }

  const { email, password } = body
  if (!email || !password) {
    return jsonResponse(res, 400, { error: 'email and password are required' }, origin)
  }

  try {
    const upstream = await fetch(
      `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({ email, password }),
      }
    )

    const data = await upstream.json()

    if (!upstream.ok) {
      return jsonResponse(res, upstream.status, {
        error: data.msg || data.error_description || 'Authentication failed',
      }, origin)
    }

    // Return clean response (hide internal details)
    return jsonResponse(res, 200, {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      token_type: 'bearer',
      user: {
        id: data.user?.id,
        email: data.user?.email,
        full_name: data.user?.user_metadata?.full_name || null,
      },
    }, origin)
  } catch (err) {
    return jsonResponse(res, 502, { error: 'Authentication service unavailable' }, origin)
  }
}

/**
 * POST /auth/refresh
 * Body: { refresh_token }
 * → Refreshes the access token
 */
async function handleAuthRefresh(req, res, origin) {
  const raw = await readBody(req)
  let body
  try {
    body = JSON.parse(raw)
  } catch {
    return jsonResponse(res, 400, { error: 'Invalid JSON' }, origin)
  }

  const { refresh_token } = body
  if (!refresh_token) {
    return jsonResponse(res, 400, { error: 'refresh_token is required' }, origin)
  }

  try {
    const upstream = await fetch(
      `${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({ refresh_token }),
      }
    )

    const data = await upstream.json()

    if (!upstream.ok) {
      return jsonResponse(res, upstream.status, {
        error: data.msg || 'Token refresh failed',
      }, origin)
    }

    return jsonResponse(res, 200, {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      token_type: 'bearer',
    }, origin)
  } catch {
    return jsonResponse(res, 502, { error: 'Authentication service unavailable' }, origin)
  }
}

/**
 * POST /v1/data
 * Body: { operation, params, jwt }
 * → Forwards to Edge Function api-supabase
 */
async function handleData(req, res, origin) {
  const raw = await readBody(req)
  let body
  try {
    body = JSON.parse(raw)
  } catch {
    return jsonResponse(res, 400, { error: 'Invalid JSON' }, origin)
  }

  const { operation, params, jwt } = body
  if (!operation) {
    return jsonResponse(res, 400, { error: "Missing 'operation'" }, origin)
  }
  if (!jwt) {
    return jsonResponse(res, 400, { error: "Missing 'jwt' — authenticate first via POST /auth/token" }, origin)
  }

  try {
    const upstream = await fetch(
      `${SUPABASE_URL}/functions/v1/api-supabase`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${jwt}`,
          'apikey': SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({ operation, params: params || {}, jwt }),
      }
    )

    const data = await upstream.json()
    return jsonResponse(res, upstream.ok ? 200 : upstream.status, data, origin)
  } catch {
    return jsonResponse(res, 502, { error: 'Data service unavailable' }, origin)
  }
}

// --- Server ---
const server = createServer(async (req, res) => {
  const origin = req.headers.origin || ''
  const url = new URL(req.url, `http://localhost:${PORT}`)
  const path = url.pathname

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin))
    return res.end()
  }

  // GET routes (info + health)
  if (req.method === 'GET') {
    if (path === '/' || path === '/health') {
      return jsonResponse(res, 200, {
        name: 'BeForBuild API',
        version: '1.0.0',
        status: 'ok',
        endpoints: {
          'POST /auth/token': 'Authenticate with email/password',
          'POST /auth/refresh': 'Refresh access token',
          'POST /v1/data': 'CRUD operations on all modules',
        },
        documentation: 'https://beforbuild.com/api-docs',
      }, origin)
    }
    return jsonResponse(res, 404, { error: `Unknown endpoint: ${path}` }, origin)
  }

  // Only POST for all other routes
  if (req.method !== 'POST') {
    return jsonResponse(res, 405, { error: 'Method not allowed. Use POST.' }, origin)
  }

  // POST routes
  try {
    if (path === '/auth/token') return await handleAuthToken(req, res, origin)
    if (path === '/auth/refresh') return await handleAuthRefresh(req, res, origin)
    if (path === '/v1/data') return await handleData(req, res, origin)

    return jsonResponse(res, 404, { error: `Unknown endpoint: ${path}` }, origin)
  } catch (err) {
    console.error('[API Proxy Error]', err)
    return jsonResponse(res, 500, { error: 'Internal server error' }, origin)
  }
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`BeForBuild API Proxy running on port ${PORT}`)
})
