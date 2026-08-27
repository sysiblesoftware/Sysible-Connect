import React, { useEffect, useRef, useState } from 'react'
import { api } from './api.js'
import Terminal from './Terminal.jsx'
import Logo from './Logo.jsx'
import { leaf, splitLeaf, closeLeaf, setRatio, firstLeafId, layout } from './layout.js'

let _ws = 0
const newWorkspace = (spec) => {
  const n = ++_ws                    // 1, 2, 3 … (pre-increment: the first is "Workspace 1")
  const root = leaf(spec || { kind: 'local', title: 'local' })
  return { id: 'ws' + n, name: 'Workspace ' + n, root, active: root.id }
}

export default function Workspace({ me, onLogout }) {
  const [spaces, setSpaces] = useState(() => [newWorkspace()])
  const [cur, setCur] = useState(0)
  const [hosts, setHosts] = useState([])
  const [adding, setAdding] = useState(false)
  const [ctrl, setCtrl] = useState({ connected: false })
  const [ctrlForm, setCtrlForm] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [ping, setPing] = useState({})        // host name -> {reachable, ms, detail}
  const [pinging, setPinging] = useState(false)
  const stageRef = useRef(null)
  const dragRef = useRef(null)   // { spaceIdx, splitId, dir }

  const loadHosts = () => api('hosts').then((d) => setHosts(d.hosts || [])).catch(() => {})
  const loadCtrl = () => api('controller').then(setCtrl).catch(() => {})
  useEffect(() => { loadHosts(); loadCtrl() }, [])

  const connectController = async ({ base_url, api_key }) => {
    try { const s = await api('controller', { method: 'POST', json: { base_url, api_key } }); setCtrl(s); setCtrlForm(false); syncController() }
    catch (e) { alert(e.message) }
  }
  const syncController = async () => {
    setSyncing(true)
    try { const d = await api('controller/sync', { method: 'POST' }); loadHosts(); alert(`Synced ${d.imported} host(s) from the Controller (${d.agents} agent, ${d.ssh_hosts} SSH).`) }
    catch (e) { alert(e.message) } finally { setSyncing(false) }
  }
  const disconnectController = async () => {
    if (!confirm('Disconnect the Controller? Synced hosts stay in your list but can no longer proxy terminals.')) return
    try { await api('controller', { method: 'DELETE' }); loadCtrl() } catch (e) { alert(e.message) }
  }

  // ---- tree ops on the current workspace ----
  const patch = (fn) => setSpaces((s) => s.map((w, i) => (i === cur ? fn(w) : w)))
  const space = spaces[cur]

  const openTerminal = (spec) => {
    const nl = leaf(spec)
    patch((w) => {
      if (!w.root) return { ...w, root: nl, active: nl.id }
      return { ...w, root: splitLeaf(w.root, w.active || firstLeafId(w.root), 'row', nl), active: nl.id }
    })
  }
  const splitActive = (dir) => {
    const nl = leaf(space.root ? specOf(space, space.active) : { kind: 'local', title: 'local' })
    patch((w) => ({ ...w, root: splitLeaf(w.root, w.active, dir, nl), active: nl.id }))
  }
  const closeActive = () => patch((w) => {
    const root = closeLeaf(w.root, w.active)
    if (!root) { const nl = leaf({ kind: 'local', title: 'local' }); return { ...w, root: nl, active: nl.id } }
    return { ...w, root, active: firstLeafId(root) }
  })
  const popOut = () => {
    const sp = specOf(space, space.active)
    if (!sp) return
    const p = new URLSearchParams({ popout: '1', kind: sp.kind, title: sp.title || sp.host || 'local' })
    if (sp.host) p.set('host', sp.host)
    window.open('/?' + p.toString(), 'sysible_term_' + space.active, 'width=900,height=560')
    closeActive()   // it now lives in the pop-out window
  }

  // ---- divider drag ----
  const onDragStart = (e, splitId, dir) => {
    e.preventDefault()
    dragRef.current = { splitId, dir }
    const move = (ev) => {
      const d = dragRef.current, box = stageRef.current
      if (!d || !box) return
      const r = box.getBoundingClientRect()
      const ratio = d.dir === 'row' ? (ev.clientX - r.left) / r.width : (ev.clientY - r.top) / r.height
      // Ratio is measured against the whole stage; good enough because a split's rect
      // spans the stage on its cross axis for top-level splits. Nested splits get a
      // proportional feel; clamped in setRatio.
      patch((w) => ({ ...w, root: setRatio(w.root, d.splitId, ratio) }))
    }
    const up = () => { dragRef.current = null; window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); document.body.style.cursor = '' }
    document.body.style.cursor = dir === 'row' ? 'col-resize' : 'row-resize'
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }

  const addHost = async (form) => {
    try { await api('hosts', { method: 'POST', json: form }); setAdding(false); loadHosts() }
    catch (e) { alert(e.message) }
  }
  const delHost = async (name) => {
    if (!confirm(`Remove host “${name}”?`)) return
    try { await api(`hosts/${encodeURIComponent(name)}`, { method: 'DELETE' }); loadHosts() } catch (e) { alert(e.message) }
  }
  const pingAll = async () => {
    setPinging(true)
    try { const d = await api('hosts/ping', { method: 'POST' }); setPing(Object.fromEntries((d.results || []).map((r) => [r.name, r]))) }
    catch (e) { alert(e.message) } finally { setPinging(false) }
  }
  const logout = async () => { try { await api('logout', { method: 'POST' }) } catch { /* */ } onLogout() }

  // Group hosts by environment for the sidebar (Unassigned last).
  const hostGroups = React.useMemo(() => {
    const m = {}
    for (const h of hosts) (m[h.environment || 'Unassigned'] ||= []).push(h)
    return Object.entries(m).sort((a, b) => (a[0] === 'Unassigned') - (b[0] === 'Unassigned') || a[0].localeCompare(b[0]))
  }, [hosts])
  const dotClass = (h) => {
    const p = ping[h.name]
    if (p) { if (p.reachable === true) return ' up'; if (p.reachable === false) return ' down' }
    return h.source === 'controller' ? ' ctrl' : ''
  }

  return (
    <div className="connect-shell">
      <aside className="side">
        <div className="side-brand"><Logo size={22} /> <span>Sysible <b>Connect</b></span></div>

        <div className="side-sec">Terminals</div>
        <button className="side-btn" onClick={() => openTerminal({ kind: 'local', title: 'local' })}>＋ Local shell</button>

        <div className="side-sec">Controller
          {ctrl.connected
            ? <button className="side-add" title="Sync the fleet from the Controller" disabled={syncing} onClick={syncController}>{syncing ? '…' : '⟳'}</button>
            : <button className="side-add" title="Connect a Controller" onClick={() => setCtrlForm(true)}>＋</button>}
        </div>
        {ctrl.connected
          ? <div className="side-host">
              <span className="side-host-open" title={ctrl.base_url}><span className="dot ok" /> {ctrl.base_url.replace(/^https?:\/\//, '')}</span>
              <button className="side-host-del" title="Disconnect" onClick={disconnectController}>✕</button>
            </div>
          : <div className="side-empty">Not connected.</div>}
        {ctrlForm && <ConnectController onCancel={() => setCtrlForm(false)} onSave={connectController} />}

        <div className="side-sec">Hosts
          <span style={{ display: 'flex', gap: 4 }}>
            <button className="side-add" title="Ping all hosts (TCP reach)" disabled={pinging || !hosts.length} onClick={pingAll}>{pinging ? '…' : '◎'}</button>
            <button className="side-add" title="Add host" onClick={() => setAdding(true)}>＋</button>
          </span>
        </div>
        {hosts.length === 0 && <div className="side-empty">No hosts yet.</div>}
        {hostGroups.map(([env, list]) => (
          <div key={env}>
            {hostGroups.length > 1 && <div className="side-envgroup">{env}</div>}
            {list.map((h) => {
              const viaCtrl = h.source === 'controller'
              const kind = viaCtrl ? 'controller' : 'ssh'
              const p = ping[h.name]
              const tip = (viaCtrl
                ? `via Controller (${h.transport || 'agent'}${h.environment ? ' · ' + h.environment : ''})`
                : `SSH ${h.user}@${h.address}:${h.port}`)
                + (p ? ` — ${p.reachable === true ? p.ms + 'ms' : p.reachable === false ? 'unreachable' : p.detail || ''}` : '')
              return (
                <div key={h.name} className="side-host">
                  <button className="side-host-open" title={tip}
                    onClick={() => openTerminal({ kind, host: h.name, title: h.name })}>
                    <span className={'dot' + dotClass(h)} /> {h.name}
                    {viaCtrl && <span className="host-badge">{h.transport === 'ssh' ? 'ssh' : 'agent'}</span>}
                  </button>
                  <button className="side-host-del" title="Remove" onClick={() => delHost(h.name)}>✕</button>
                </div>
              )
            })}
          </div>
        ))}
        {adding && <AddHost onCancel={() => setAdding(false)} onSave={addHost} />}

        <div className="side-foot">
          <span className="muted">{me.user}</span>
          <button className="side-btn ghost" onClick={logout}>Sign out</button>
        </div>
      </aside>

      <main className="main">
        <div className="tabbar">
          {spaces.map((w, i) => (
            <button key={w.id} className={'tab' + (i === cur ? ' active' : '')}
              onDoubleClick={() => { const n = prompt('Workspace name', w.name); if (n) setSpaces((s) => s.map((x, j) => (j === i ? { ...x, name: n } : x))) }}
              onClick={() => setCur(i)}>{w.name}
              {spaces.length > 1 && <span className="tab-x" onClick={(e) => { e.stopPropagation(); setSpaces((s) => s.filter((_, j) => j !== i)); setCur((c) => Math.max(0, c - (i <= c ? 1 : 0))) }}>✕</span>}
            </button>
          ))}
          <button className="tab-add" title="New workspace" onClick={() => { setSpaces((s) => [...s, newWorkspace()]); setCur(spaces.length) }}>＋</button>
          <div className="tab-tools">
            <button className="tool" title="Split right — new pane beside this one" onClick={() => splitActive('row')}>◫</button>
            <button className="tool" title="Split down — new pane below this one" onClick={() => splitActive('col')}>⊟</button>
            <button className="tool" title="Pop out" onClick={popOut}>⇱</button>
            <button className="tool danger" title="Close pane" onClick={closeActive}>✕</button>
          </div>
        </div>

        <div className="stage" ref={stageRef}>
          {/* Every workspace's terminals stay mounted (inactive ones hidden), so
              switching tabs never drops a session. */}
          {spaces.map((w, i) => {
            const { tiles, dividers } = layout(w.root)
            return (
              <div key={w.id} className="ws-layer" style={{ display: i === cur ? 'block' : 'none' }}>
                {tiles.map((t) => (
                  <div key={t.id} className={'tile' + (t.id === w.active ? ' active' : '')}
                    style={rectStyle(t.rect)} onMouseDown={() => patch((x) => ({ ...x, active: t.id }))}>
                    <div className="tile-h">
                      <span className="tile-title">{t.spec.kind === 'ssh' ? `⚡ ${t.spec.title}` : `▸ ${t.spec.title || 'local'}`}</span>
                    </div>
                    <div className="tile-body"><Terminal spec={t.spec} /></div>
                  </div>
                ))}
                {dividers.map((d) => (
                  <div key={d.id} className={'divider ' + d.dir} style={rectStyle(d.rect)}
                    onMouseDown={(e) => onDragStart(e, d.id, d.dir)} />
                ))}
              </div>
            )
          })}
        </div>
      </main>
    </div>
  )
}

const rectStyle = (r) => ({ left: r.left + '%', top: r.top + '%', width: r.w + '%', height: r.h + '%' })

// The spec of a leaf id in a workspace (walk the tree).
function specOf(space, leafId) {
  const walk = (n) => {
    if (!n) return null
    if (n.t === 'leaf') return n.id === leafId ? n.spec : null
    return walk(n.a) || walk(n.b)
  }
  return walk(space.root)
}

function ConnectController({ onCancel, onSave }) {
  const [f, setF] = useState({ base_url: '', api_key: '' })
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }))
  return (
    <div className="add-host">
      <input placeholder="Controller URL (https://host:9000)" value={f.base_url} onChange={(e) => set('base_url', e.target.value)} autoFocus />
      <input placeholder="Backend API key" type="password" value={f.api_key} onChange={(e) => set('api_key', e.target.value)} />
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="side-btn ghost" onClick={onCancel}>Cancel</button>
        <button className="side-btn" onClick={() => onSave(f)}>Connect &amp; sync</button>
      </div>
    </div>
  )
}

function AddHost({ onCancel, onSave }) {
  const [f, setF] = useState({ name: '', address: '', user: 'root', port: 22, password: '', key: '' })
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }))
  return (
    <div className="add-host">
      <input placeholder="Name" value={f.name} onChange={(e) => set('name', e.target.value)} autoFocus />
      <input placeholder="Address (host / IP)" value={f.address} onChange={(e) => set('address', e.target.value)} />
      <div className="row">
        <input placeholder="user" value={f.user} onChange={(e) => set('user', e.target.value)} />
        <input placeholder="port" type="number" value={f.port} onChange={(e) => set('port', Number(e.target.value))} style={{ width: 70 }} />
      </div>
      <input placeholder="Password (optional)" type="password" value={f.password} onChange={(e) => set('password', e.target.value)} />
      <textarea placeholder="Private key (optional, PEM)" rows={2} value={f.key} onChange={(e) => set('key', e.target.value)} />
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="side-btn ghost" onClick={onCancel}>Cancel</button>
        <button className="side-btn" onClick={() => onSave(f)}>Add host</button>
      </div>
    </div>
  )
}
