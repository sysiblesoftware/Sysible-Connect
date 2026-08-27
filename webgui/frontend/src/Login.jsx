import React, { useState } from 'react'
import { api } from './api.js'

export default function Login({ onAuthed }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [np, setNp] = useState('')
  const [changing, setChanging] = useState(null)   // {user} once a must-change login lands
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      const d = await api('login', { method: 'POST', json: { username: u, password: p } })
      if (d.must_change) setChanging(d); else onAuthed(d)
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  const changePw = async (e) => {
    e.preventDefault(); setErr(''); setBusy(true)
    try { await api('change-password', { method: 'POST', json: { new_password: np } }); onAuthed(changing) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <form className="login" onSubmit={changing ? changePw : submit}>
        <div className="login-brand">Sysible <b>Connect</b></div>
        {changing ? (
          <>
            <div className="muted">Choose a new password (at least 8 characters).</div>
            <input type="password" placeholder="New password" value={np} autoFocus
              onChange={(e) => setNp(e.target.value)} />
          </>
        ) : (
          <>
            <input placeholder="Username" value={u} autoFocus onChange={(e) => setU(e.target.value)} />
            <input type="password" placeholder="Password" value={p} onChange={(e) => setP(e.target.value)} />
          </>
        )}
        {err && <div className="login-err">{err}</div>}
        <button className="primary" disabled={busy}>{busy ? '…' : changing ? 'Set password' : 'Sign in'}</button>
      </form>
    </div>
  )
}
