import webpush from 'web-push'

interface Env {
  SUBSCRIPTIONS: KVNamespace
  DB: D1Database
  VAPID_PUBLIC_KEY: string
  VAPID_PRIVATE_KEY: string
  VAPID_SUBJECT: string
  AUTH_JWT_SECRET: string
}

interface WebPushSubscription {
  endpoint: string
  keys: { p256dh: string; auth: string }
}

interface DueItem {
  key: string
  title: string
  dueDate: string
  url: string
}

interface StoredSubscription {
  subscription: WebPushSubscription
  items: DueItem[]
  notified: string[]
}

// ---------- общие утилиты ----------

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  }
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  })
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlToBytes(b64url: string): Uint8Array {
  let str = b64url.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) str += '='
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function stringToBase64Url(str: string): string {
  return bytesToBase64Url(new TextEncoder().encode(str))
}

function base64UrlToString(b64url: string): string {
  const bytes = base64UrlToBytes(b64url)
  return new TextDecoder().decode(bytes)
}

// ---------- пароли: PBKDF2 через встроенный Web Crypto, без внешних либ ----------

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, key, 256)
  return `${bytesToBase64Url(salt)}:${bytesToBase64Url(new Uint8Array(bits))}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltB64, hashB64] = stored.split(':')
  if (!saltB64 || !hashB64) return false
  const salt = base64UrlToBytes(saltB64)
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, key, 256)
  return bytesToBase64Url(new Uint8Array(bits)) === hashB64
}

// ---------- токены: самодельный JWT (HMAC-SHA256), без внешних либ ----------

interface TokenPayload {
  sub: string
  username: string
  exp: number
}

async function hmacSign(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return bytesToBase64Url(new Uint8Array(sig))
}

async function createToken(payload: TokenPayload, secret: string): Promise<string> {
  const headerB64 = stringToBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payloadB64 = stringToBase64Url(JSON.stringify(payload))
  const signature = await hmacSign(`${headerB64}.${payloadB64}`, secret)
  return `${headerB64}.${payloadB64}.${signature}`
}

async function verifyToken(token: string, secret: string): Promise<TokenPayload | null> {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [headerB64, payloadB64, signature] = parts
  const expected = await hmacSign(`${headerB64}.${payloadB64}`, secret)
  if (expected !== signature) return null
  try {
    const payload: TokenPayload = JSON.parse(base64UrlToString(payloadB64))
    if (payload.exp < Date.now() / 1000) return null
    return payload
  } catch {
    return null
  }
}

async function requireAuth(request: Request, env: Env): Promise<TokenPayload | null> {
  const header = request.headers.get('Authorization')
  if (!header?.startsWith('Bearer ')) return null
  return verifyToken(header.slice(7), env.AUTH_JWT_SECRET)
}

// ---------- push-утилиты (без изменений из прошлой версии) ----------

function subscriptionKey(sub: WebPushSubscription): string {
  return sub.endpoint ?? ''
}

function daysUntil(dueDate: string): number {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const due = new Date(dueDate + 'T00:00:00')
  return Math.round((due.getTime() - today.getTime()) / 86_400_000)
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() })
    }

    const url = new URL(request.url)

    // ---------- регистрация ----------
    if (url.pathname === '/auth/register' && request.method === 'POST') {
      const body = await request.json<{ username: string; password: string }>()
      const username = body.username?.trim().toLowerCase()
      const password = body.password

      if (!username || username.length < 3) return json({ error: 'Логин минимум 3 символа' }, 400)
      if (!password || password.length < 6) return json({ error: 'Пароль минимум 6 символов' }, 400)

      const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
      if (existing) return json({ error: 'Такой логин уже занят' }, 409)

      const userId = crypto.randomUUID()
      const passwordHash = await hashPassword(password)
      await env.DB.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .bind(userId, username, passwordHash, new Date().toISOString())
        .run()

      const token = await createToken({ sub: userId, username, exp: Math.floor(Date.now() / 1000) + 90 * 86400 }, env.AUTH_JWT_SECRET)
      return json({ token, userId, username })
    }

    // ---------- вход ----------
    if (url.pathname === '/auth/login' && request.method === 'POST') {
      const body = await request.json<{ username: string; password: string }>()
      const username = body.username?.trim().toLowerCase()
      const password = body.password

      const user = await env.DB.prepare('SELECT id, password_hash FROM users WHERE username = ?').bind(username).first<{ id: string; password_hash: string }>()
      if (!user) return json({ error: 'Неверный логин или пароль' }, 401)

      const valid = await verifyPassword(password, user.password_hash)
      if (!valid) return json({ error: 'Неверный логин или пароль' }, 401)

      const token = await createToken({ sub: user.id, username, exp: Math.floor(Date.now() / 1000) + 90 * 86400 }, env.AUTH_JWT_SECRET)
      return json({ token, userId: user.id, username })
    }

    // ---------- получить данные с сервера ----------
    if (url.pathname === '/sync' && request.method === 'GET') {
      const auth = await requireAuth(request, env)
      if (!auth) return json({ error: 'unauthorized' }, 401)

      const row = await env.DB.prepare('SELECT goals_json, updated_at FROM user_data WHERE user_id = ?').bind(auth.sub).first<{ goals_json: string; updated_at: string }>()
      if (!row) return json({ goals: [], updatedAt: null })
      return json({ goals: JSON.parse(row.goals_json), updatedAt: row.updated_at })
    }

    // ---------- записать данные на сервер ----------
    if (url.pathname === '/sync' && request.method === 'PUT') {
      const auth = await requireAuth(request, env)
      if (!auth) return json({ error: 'unauthorized' }, 401)

      const body = await request.json<{ goals: unknown[] }>()
      const now = new Date().toISOString()
      await env.DB.prepare(
        `INSERT INTO user_data (user_id, goals_json, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET goals_json = excluded.goals_json, updated_at = excluded.updated_at`
      ).bind(auth.sub, JSON.stringify(body.goals), now).run()

      return json({ ok: true, updatedAt: now })
    }

    // ---------- push-подписка (без изменений) ----------
    if (url.pathname === '/subscribe' && request.method === 'POST') {
      const body = await request.json<{ subscription: WebPushSubscription; items: DueItem[] }>()
      const key = subscriptionKey(body.subscription)
      if (!key) return json({ error: 'invalid subscription' }, 400)

      const existing = await env.SUBSCRIPTIONS.get<StoredSubscription>(key, 'json')
      const record: StoredSubscription = {
        subscription: body.subscription,
        items: body.items,
        notified: existing?.notified ?? [],
      }
      await env.SUBSCRIPTIONS.put(key, JSON.stringify(record))
      return json({ ok: true })
    }

    if (url.pathname === '/unsubscribe' && request.method === 'POST') {
      const body = await request.json<{ subscription: WebPushSubscription }>()
      const key = subscriptionKey(body.subscription)
      if (key) await env.SUBSCRIPTIONS.delete(key)
      return json({ ok: true })
    }

    return json({ error: 'not found' }, 404)
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    webpush.setVapidDetails(env.VAPID_SUBJECT, env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY)

    const list = await env.SUBSCRIPTIONS.list()

    for (const key of list.keys) {
      const record = await env.SUBSCRIPTIONS.get<StoredSubscription>(key.name, 'json')
      if (!record) continue

      const notified = new Set(record.notified)
      let changed = false

      for (const item of record.items) {
        const days = daysUntil(item.dueDate)
        if (days > 1) continue
        if (notified.has(item.key)) continue

        const body = days === 0 ? 'Сегодня' : days < 0 ? `Просрочено на ${-days} дн.` : 'Завтра'

        try {
          await webpush.sendNotification(record.subscription as any, JSON.stringify({ title: item.title, body, url: item.url, tag: item.key }))
          notified.add(item.key)
          changed = true
        } catch (err: any) {
          if (err.statusCode === 410 || err.statusCode === 404) {
            await env.SUBSCRIPTIONS.delete(key.name)
            changed = false
            break
          }
        }
      }

      if (changed) {
        record.notified = Array.from(notified)
        await env.SUBSCRIPTIONS.put(key.name, JSON.stringify(record))
      }
    }
  },
}