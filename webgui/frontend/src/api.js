// Tiny fetch wrapper + terminal websocket URL builder. Same-origin: the session
// cookie rides along automatically (httponly), so there is no token to manage here.
export async function api(path, opts = {}) {
  const res = await fetch('/api/' + path, {
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
  return `${proto}://${location.host}/api/terminal/ws?${p.toString()}`
}
