// Tiny fetch wrapper + terminal websocket URL builder. Same-origin: the session
// cookie rides along automatically (httponly), so there is no token to manage here.

// URL prefix the console is served under (see vite.config base). "" standalone,
// "/connect" behind the SLOP gateway, which path-routes /connect/* to this app on
// one shared origin. import.meta.env.BASE_URL carries the build-time base; every
// request AND the terminal websocket is prefixed with it so the SAME code works in
// both layouts (the gateway strips the prefix before the backend sees it).
export const BASE = (import.meta.env.BASE_URL || '/').replace(/\/+$/, '')
export const apiUrl = (p) => BASE + p

export async function api(path, opts = {}) {
  const res = await fetch(apiUrl('/api/' + path), {
    method: opts.method || 'GET',
    headers: opts.json ? { 'Content-Type': 'application/json' } : undefined,
    body: opts.json ? JSON.stringify(opts.json) : undefined,
  })
  if (!res.ok) {
    let detail
    try { detail = (await res.json()).detail } catch { /* non-JSON error */ }
    const err = new Error(detail || res.statusText)
    err.status = res.status
    throw err
  }
  try { return await res.json() } catch { return {} }
}

export function terminalWsUrl({ kind, host, cols, rows }) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const p = new URLSearchParams({ kind, cols: String(cols || 80), rows: String(rows || 24) })
  if (host) p.set('host', host)
  return `${proto}://${location.host}${BASE}/api/terminal/ws?${p.toString()}`
}
