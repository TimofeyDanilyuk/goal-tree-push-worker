import webpush from 'web-push'

interface Env {
  SUBSCRIPTIONS: KVNamespace
  VAPID_PUBLIC_KEY: string
  VAPID_PRIVATE_KEY: string
  VAPID_SUBJECT: string
}

interface DueItem {
  key: string
  title: string
  dueDate: string // YYYY-MM-DD
  url: string
}

interface StoredSubscription {
  subscription: PushSubscriptionJSON
  items: DueItem[]
  notified: string[]
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  })
}

function subscriptionKey(sub: PushSubscriptionJSON): string {
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

    if (url.pathname === '/subscribe' && request.method === 'POST') {
      const body = await request.json<{ subscription: PushSubscriptionJSON; items: DueItem[] }>()
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
      const body = await request.json<{ subscription: PushSubscriptionJSON }>()
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
          await webpush.sendNotification(
            record.subscription as any,
            JSON.stringify({ title: item.title, body, url: item.url })
          )
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