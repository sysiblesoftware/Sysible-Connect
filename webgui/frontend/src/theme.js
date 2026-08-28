// Light / dark theme, persisted per browser. Dark is the default look; the app
// follows the OS preference until the user makes an explicit choice, after which
// that choice sticks. The chosen theme is written as data-theme on <html> and the
// CSS in styles.css defines both palettes as tokens.
const KEY = 'sysible-connect-theme'

export function initTheme() {
  // Apply a stored explicit choice on boot (before first paint, from main.jsx).
  try {
    const t = localStorage.getItem(KEY)
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t)
  } catch { /* storage may be blocked; fall back to OS preference via CSS */ }
}

export function getTheme() {
  const explicit = document.documentElement.getAttribute('data-theme')
  if (explicit === 'light' || explicit === 'dark') return explicit
  try {
    const t = localStorage.getItem(KEY)
    if (t === 'light' || t === 'dark') return t
  } catch { /* */ }
  return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'
}

export function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t)
  try { localStorage.setItem(KEY, t) } catch { /* */ }
}

export function toggleTheme() {
  const next = getTheme() === 'light' ? 'dark' : 'light'
  setTheme(next)
  return next
}
