import React, { useEffect, useState } from 'react'
import { api } from './api.js'
import Login from './Login.jsx'
import Workspace from './Workspace.jsx'
import Terminal from './Terminal.jsx'

export default function App() {
  // Pop-out window: a single full-window terminal (opened from a tile's ⇱ button).
  const params = new URLSearchParams(location.search)
  if (params.get('popout') === '1') {
    const spec = {
      kind: params.get('kind') || 'local',
      host: params.get('host') || '',
      title: params.get('title') || (params.get('host') || 'local'),
    }
    document.title = `${spec.title} — Sysible Connect`
    return <div className="popout"><Terminal spec={spec} /></div>
  }

  const [me, setMe] = useState(undefined)   // undefined = loading, null = logged out
  useEffect(() => { api('me').then((d) => setMe(d.user ? d : null)).catch(() => setMe(null)) }, [])

  if (me === undefined) return <div className="center muted">Loading…</div>
  if (!me) return <Login onAuthed={(d) => setMe(d)} />
  return <Workspace me={me} onLogout={() => setMe(null)} />
}
