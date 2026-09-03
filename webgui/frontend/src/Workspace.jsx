import React, { useEffect, useRef, useState } from 'react'
import { api, apiUrl, BASE } from './api.js'
import Terminal from './Terminal.jsx'
import Logo from './Logo.jsx'
import { IconSplitRight, IconSplitDown, IconPopout, IconClose, IconSave, IconSun, IconMoon } from './icons.jsx'
import { getTheme, toggleTheme } from './theme.js'
import { leaf, splitLeaf, closeLeaf, setRatio, firstLeafId, layout, dropTarget } from './layout.js'

let _ws = 0
const newWorkspace = (spec) => {
  const n = ++_ws                    // 1, 2, 3 … (pre-increment: the first is "Workspace 1")
  // A workspace opens BLANK — no automatic local terminal. Drag a host onto it (or
  // use ＋ Local shell) to open one. Pass a spec only to seed one deliberately.
  const root = spec ? leaf(spec) : null
  return { id: 'ws' + n, name: 'Workspace ' + n, root, active: root ? root.id : null }
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
  const [fleet, setFleet] = useState(null)    // {label, loading} | {label, results}
  const [filesFor, setFilesFor] = useState(null)   // host name whose Files modal is open
  const [theme, setTheme] = useState(getTheme())
  const stageRef = useRef(null)
  const dragRef = useRef(null)   // { spaceIdx, splitId, dir }

  const loadHosts = () => api('hosts').then((d) => setHosts(d.hosts || [])).catch(() => {})
  const loadCtrl = () => api('controller').then(setCtrl).catch(() => {})
  useEffect(() => {
    loadHosts()
    // Load the Controller status; when we're auto-attached to the local Controller over
    // SSO (no manual login), pull its fleet once, quietly — so hosts appear on their own,
    // like when Connect was part of the Controller.
    api('controller').then((s) => {
      setCtrl(s)
      if (s && s.connected && s.sso) api('controller/sync', { method: 'POST' }).then(() => loadHosts()).catch(() => {})
    }).catch(() => {})
  }, [])

  const connectController = async (form) => {
    try { const s = await api('controller', { method: 'POST', json: form }); setCtrl(s); setCtrlForm(false); syncController() }
    catch (e) { alert(e.message) }
  }
  const syncController = async () => {
    setSyncing(true)
    try { const d = await api('controller/sync', { method: 'POST' }); loadHosts()
      alert(`Synced ${d.imported} host(s) from the Controller (${d.agents} agent, ${d.ssh_hosts} SSH`
        + (d.offline ? ` · ${d.online} online, ${d.offline} offline).` : ').')) }
    catch (e) { alert(e.message) } finally { setSyncing(false) }
  }
  const disconnectController = async () => {
    if (!confirm('Disconnect the Controller? Synced hosts stay in your list but can no longer proxy terminals.')) return
    try { await api('controller', { method: 'DELETE' }); loadCtrl() } catch (e) { alert(e.message) }
  }

  // ---- tree ops on the current workspace ----
  const patch = (fn) => setSpaces((s) => s.map((w, i) => (i === cur ? fn(w) : w)))
  const space = spaces[cur]

  // Open a host. `at` (from a drop on a tile's edge) says WHERE: which pane to split
  // and in which direction. Without it every host landed to the right of the active
  // pane, which meant two different hosts could never be stacked vertically — the
  // layout tree supported 'col' all along, nothing could ask for it.
  const openTerminal = (spec, at = null) => {
    const nl = leaf(spec)
    patch((w) => {
      if (!w.root) return { ...w, root: nl, active: nl.id }
      const target = at?.id || w.active || firstLeafId(w.root)
      return { ...w, root: splitLeaf(w.root, target, at?.dir || 'row', nl, at?.before || false),
               active: nl.id }
    })
  }
  const splitActive = (dir) => {
    if (!space.root) { openTerminal({ kind: 'local', title: 'local' }); return }
    const nl = leaf(specOf(space, space.active) || { kind: 'local', title: 'local' })
    patch((w) => ({ ...w, root: splitLeaf(w.root, w.active, dir, nl), active: nl.id }))
  }

  // ---- drag a host from the sidebar onto the stage to open its terminal ----
  const DND_TYPE = 'application/x-sysible-host'
  // The pane+edge the pointer is over, so the drop is previewed before it happens.
  const [dropAt, setDropAt] = useState(null)
  const [dropAtEmpty, setDropAtEmpty] = useState(false)
  const dragOver = !!dropAt || dropAtEmpty
  const onHostDragStart = (e, spec) => {
    try {
      e.dataTransfer.setData(DND_TYPE, JSON.stringify(spec))
      e.dataTransfer.setData('text/plain', spec.host || spec.title || 'terminal')
      e.dataTransfer.effectAllowed = 'copy'
    } catch { /* dnd unavailable */ }
  }
  // Where in the stage (as a %) the pointer is, so the drop target can be resolved
  // against the same rects the tiles are laid out with.
  const stagePct = (e) => {
    const r = stageRef.current?.getBoundingClientRect()
    if (!r || !r.width || !r.height) return null
    return { x: ((e.clientX - r.left) / r.width) * 100, y: ((e.clientY - r.top) / r.height) * 100 }
  }
  const onStageDragOver = (e) => {
    if (!Array.from(e.dataTransfer.types || []).includes(DND_TYPE)) return
    e.preventDefault(); e.dataTransfer.dropEffect = 'copy'
    const p = stagePct(e)
    const at = p && space.root ? dropTarget(space.root, p.x, p.y) : null
    setDropAtEmpty(!space.root)
    setDropAt(at)
  }
  const onStageDrop = (e) => {
    e.preventDefault()
    const at = dropAt
    setDropAt(null); setDropAtEmpty(false)
    try {
      const spec = JSON.parse(e.dataTransfer.getData(DND_TYPE))
      if (spec && (spec.kind === 'local' || spec.host)) openTerminal(spec, at)
    } catch { /* not a host drag */ }
  }
  const onStageDragLeave = (e) => {
    // Only clear when the pointer really left the stage — dragleave also fires when
    // it crosses between the tiles inside it, and clearing there makes the preview
    // flicker and the drop land nowhere.
    if (e.currentTarget.contains(e.relatedTarget)) return
    setDropAt(null); setDropAtEmpty(false)
  }
  const closeActive = () => space.active && closeTile(space.active)
  // Close a specific pane by id. Closing the last pane leaves the workspace BLANK
  // (drag a host on to open another), rather than respawning a local shell.
  const closeTile = (id) => patch((w) => {
    const root = closeLeaf(w.root, id)
    if (!root) return { ...w, root: null, active: null }
    return { ...w, root, active: (w.active === id ? firstLeafId(root) : w.active) }
  })
  const popOut = () => {
    const sp = specOf(space, space.active)
    if (!sp) return
    const p = new URLSearchParams({ popout: '1', kind: sp.kind, title: sp.title || sp.host || 'local' })
    if (sp.host) p.set('host', sp.host)
    // BASE, not '/'. Behind the SLOP gateway this console is served under /connect/,
    // so a bare '/' is the SLOP PORTAL — popping a terminal out opened the portal's
    // landing page in a little window and threw the session away. Standalone Connect
    // builds with BASE '', where this is unchanged.
    const win = window.open(`${BASE}/?${p.toString()}`,
                            'sysible_term_' + space.active, 'width=900,height=560')
    // Only give up the tile once the window really opened. A blocked popup used to
    // close the pane anyway, so the session was destroyed and nothing replaced it.
    if (!win) {
      alert('Your browser blocked the pop-out window. Allow pop-ups for this site '
            + 'and try again — the terminal has been left where it is.')
      return
    }
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

  // ---- fleet actions: run one command across every host ----
  const fleetRun = async (command, label) => {
    if (!hosts.length) { alert('No hosts yet.'); return }
    setFleet({ label, loading: true })
    try { const d = await api('fleet/run', { method: 'POST', json: { command } }); setFleet({ label, results: d.results || [] }) }
    catch (e) { setFleet(null); alert(e.message) }
  }
  const runScriptAll = () => { const c = prompt('Command to run on ALL hosts:'); if (c && c.trim()) fleetRun(c, 'Run on all') }
  const restartAgentAll = () => { if (confirm('Restart the Sysible agent on all hosts?')) fleetRun('sudo systemctl restart sysible-agent', 'Restart agent') }
  const dangerAll = (word, cmd, label) => {
    if (prompt(`This will ${label.toUpperCase()} every host. Type ${word} to confirm:`) === word) fleetRun(cmd, label)
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
    // Reflect the Controller's own liveness view for agent hosts synced from it.
    if (h.online === true) return ' up'
    if (h.online === false) return ' down'
    return h.source === 'controller' ? ' ctrl' : ''
  }
  const agoText = (sec) => {
    if (!sec) return 'never'
    const d = Math.max(0, Math.floor(Date.now() / 1000 - sec))
    if (d < 60) return d + 's ago'
    if (d < 3600) return Math.floor(d / 60) + 'm ago'
    if (d < 86400) return Math.floor(d / 3600) + 'h ago'
    return Math.floor(d / 86400) + 'd ago'
  }

  return (
    <div className="connect-shell">
      <aside className="side">
        <div className="side-brand"><Logo size={22} /> <span>Sysible <b>Connect</b></span></div>

        <div className="side-sec">Terminals</div>
        <button className="side-btn" draggable
          onDragStart={(e) => onHostDragStart(e, { kind: 'local', title: 'local' })}
          onClick={() => openTerminal({ kind: 'local', title: 'local' })}>＋ Local shell</button>

        <div className="side-sec">Controller
          {ctrl.connected
            ? <button className="side-add" title="Sync the fleet from the Controller" disabled={syncing} onClick={syncController}>{syncing ? '…' : '⟳'}</button>
            : <button className="side-add" title="Connect a Controller" onClick={() => setCtrlForm(true)}>＋</button>}
        </div>
        {ctrl.connected
          ? <>
              <div className="side-host">
                <span className="side-host-open" title={ctrl.base_url}><span className="dot ok" /> {ctrl.base_url.replace(/^https?:\/\//, '')}</span>
                <button className="side-host-del" title="Disconnect" onClick={disconnectController}>✕</button>
              </div>
              {/* Who terminals & commands run as on each host. Under SSO this is the
                  signed-in SLOP operator, forwarded per request — so the fallback copy
                  must not tell an SSO user to "reconnect with a username & password":
                  there is nothing to reconnect, and SLOP is the only door. */}
              <div className="side-runas" title={ctrl.run_as
                ? `Terminals & commands run as “${ctrl.run_as}” on each host (that account + its sudo), and are attributed to it in the Controller's audit log.`
                : ctrl.sso
                  ? 'Signed in through SLOP, but this account isn’t provisioned on the Controller yet, so terminals run as the Controller’s default account. Add it in SLOP Administration → Accounts.'
                  : 'Connected with an API key only — terminals run as the Controller’s default account. Reconnect with a username & password to run as your own account.'}>
                {ctrl.run_as
                  ? <>runs as <b>{ctrl.run_as}</b></>
                  : (ctrl.sso ? 'no run-as (not provisioned)' : 'API-key connect (no run-as)')}
              </div>
            </>
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
              const ctrlLive = viaCtrl && h.transport === 'agent' && h.online != null
                ? (h.online ? ` — online (seen ${agoText(h.last_seen)})` : ` — OFFLINE (last seen ${agoText(h.last_seen)})`)
                : ''
              const tip = (viaCtrl
                ? `via Controller (${h.transport || 'agent'}${h.environment ? ' · ' + h.environment : ''})`
                : `SSH ${h.user}@${h.address}:${h.port}`)
                + ctrlLive
                + (p ? ` — ${p.reachable === true ? p.ms + 'ms' : p.reachable === false ? 'unreachable' : p.detail || ''}` : '')
              return (
                <div key={h.name} className="side-host">
                  <button className="side-host-open" title={tip + ' — click to open, or drag onto a pane\'s edge to split (top/bottom stacks, left/right sits alongside)'} draggable
                    onDragStart={(e) => onHostDragStart(e, { kind, host: h.name, title: h.name })}
                    onClick={() => openTerminal({ kind, host: h.name, title: h.name })}>
                    <span className={'dot' + dotClass(h)} /> {h.name}
                    {viaCtrl && <span className="host-badge">{h.transport === 'ssh' ? 'ssh' : 'agent'}</span>}
                  </button>
                  {!viaCtrl && <button className="side-host-del" title="Files (SFTP)" onClick={() => setFilesFor(h.name)}>⌸</button>}
                  <button className="side-host-del" title="Remove" onClick={() => delHost(h.name)}>✕</button>
                </div>
              )
            })}
          </div>
        ))}
        {adding && <AddHost onCancel={() => setAdding(false)} onSave={addHost} />}

        {hosts.length > 0 && <>
          <div className="side-sec">Fleet actions <span className="side-sec-count">{hosts.length}</span></div>
          <div className="fleet-group">
            <button className="fleet-btn" onClick={runScriptAll}>Run script on all…</button>
            <button className="fleet-btn" onClick={restartAgentAll}>Restart agent on all</button>
            <div className="fleet-sep">Destructive</div>
            <button className="fleet-btn danger" onClick={() => dangerAll('REBOOT', 'sudo reboot', 'reboot')}>Reboot all</button>
            <button className="fleet-btn danger" onClick={() => dangerAll('POWEROFF', 'sudo poweroff', 'power off')}>Power off all</button>
          </div>
        </>}

        <div className="side-foot">
          <span className="muted">{me.user}</span>
          <div className="side-foot-actions">
            <button className="icon-btn" title={theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'}
              aria-label="Toggle theme" onClick={() => setTheme(toggleTheme())}>
              {theme === 'light' ? <IconMoon /> : <IconSun />}
            </button>
            <button className="side-btn ghost" onClick={logout}>Sign out</button>
          </div>
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
          {/* Labelled, not a bare ＋: at the far right of a wide tab bar an unlabeled
              glyph reads as decoration, and "there's no real way to add a blank
              workspace" is what that costs. */}
          <button className="tab-add" title="New workspace (blank)"
            onClick={() => { setSpaces((s) => [...s, newWorkspace()]); setCur(spaces.length) }}>＋ Workspace</button>
          <div className="tab-tools">
            <button className="tool" title="Split right — new pane beside this one" aria-label="Split right" onClick={() => splitActive('row')}><IconSplitRight /></button>
            <button className="tool" title="Split down — new pane below this one" aria-label="Split down" onClick={() => splitActive('col')}><IconSplitDown /></button>
            <button className="tool" title="Pop out into its own window" aria-label="Pop out" onClick={popOut}><IconPopout /></button>
          </div>
        </div>

        <div className={'stage' + (dragOver ? ' drag-over' : '')} ref={stageRef}
          onDragOver={onStageDragOver} onDragLeave={onStageDragLeave} onDrop={onStageDrop}>
          {!space.root && (
            <div className="stage-empty">
              <div className="stage-empty-card">
                <div className="stage-empty-title">Empty workspace</div>
                <div className="stage-empty-sub">
                  Drag a host from the sidebar here, or open a shell on this machine.
                </div>
                <button className="stage-empty-btn"
                  onClick={() => openTerminal({ kind: 'local', title: 'local' })}>
                  Open a local shell
                </button>
                <div className="stage-empty-hint">
                  Already have a pane? Drop a host on its <b>top or bottom edge</b> to
                  stack them, or its <b>left or right edge</b> to sit them side by side.
                </div>
              </div>
            </div>
          )}
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
                      <button className="tile-x" title="Close this terminal" aria-label="Close this terminal"
                        onClick={(e) => { e.stopPropagation(); closeTile(t.id) }}><IconClose /></button>
                    </div>
                    <div className="tile-body"><Terminal spec={t.spec} /></div>
                  </div>
                ))}
                {dividers.map((d) => (
                  <div key={d.id} className={'divider ' + d.dir} style={rectStyle(d.rect)}
                    onMouseDown={(e) => onDragStart(e, d.id, d.dir)} />
                ))}
                {/* Drop preview: the exact half the dragged host will take. Shown
                    only on the workspace being dropped into. */}
                {i === cur && dropAt && (
                  <div className="drop-preview" style={rectStyle(dropAt.rect)}>
                    <span>{dropAt.dir === 'col' ? 'Stack here' : 'Split here'}</span>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </main>

      {fleet && <FleetResults data={fleet} onClose={() => setFleet(null)} />}
      {filesFor && <FilesModal host={filesFor} onClose={() => setFilesFor(null)} />}
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

function FilesModal({ host, onClose }) {
  const [data, setData] = useState(null)   // {path, entries}
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const base = `hosts/${encodeURIComponent(host)}/files`
  const load = async (p) => {
    setBusy(true); setErr('')
    try { const d = await api(`${base}/list`, { method: 'POST', json: { path: p } }); setData(d) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  useEffect(() => { load('.') }, [])   // eslint-disable-line
  const join = (name) => (data.path.replace(/\/$/, '') + '/' + name)
  const up = () => load(data.path.replace(/\/[^/]+\/?$/, '') || '/')
  const dl = (name) => window.open(apiUrl(`/api/${base}/download?path=${encodeURIComponent(join(name))}`), '_blank')
  const upload = async (fileList) => {
    const f = fileList && fileList[0]; if (!f) return
    setBusy(true); setErr('')
    try {
      const fd = new FormData(); fd.append('file', f); fd.append('path', data.path.replace(/\/$/, '') + '/')
      const res = await fetch(apiUrl(`/api/${base}/upload`), { method: 'POST', body: fd })
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText)
      load(data.path)
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-h"><b>Files · {host}</b>
          <button className="side-host-del" style={{ marginLeft: 'auto' }} onClick={onClose}>✕</button></div>
        <div className="modal-body">
          <div className="add-host .row" style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 8 }}>
            <button className="side-btn ghost sm" onClick={up} disabled={busy || !data}>↑ Up</button>
            <code className="muted" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data?.path || '…'}</code>
            <label className="side-btn sm" style={{ cursor: 'pointer' }}>Upload
              <input type="file" style={{ display: 'none' }} onChange={(e) => upload(e.target.files)} /></label>
          </div>
          {err && <div className="login-err">{err}</div>}
          {busy && <div className="muted">…</div>}
          {data?.entries?.map((e) => (
            <div key={e.name} className="file-row">
              <button className="file-name" onClick={() => e.dir ? load(join(e.name)) : dl(e.name)}>
                {e.dir ? '📁' : '📄'} {e.name}</button>
              {!e.dir && <>
                <span className="muted" style={{ fontSize: 11 }}>{e.size}B</span>
                <button className="side-btn ghost sm" title="Download" aria-label="Download" onClick={() => dl(e.name)}><IconSave /></button>
              </>}
            </div>
          ))}
          {data && !data.entries.length && <div className="muted">(empty)</div>}
        </div>
      </div>
    </div>
  )
}

function FleetResults({ data, onClose }) {
  const ok = (data.results || []).filter((r) => r.ok).length
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-h">
          <b>{data.label}</b>
          {data.loading ? <span className="muted"> · running…</span>
            : <span className="muted"> · {ok}/{data.results.length} ok</span>}
          <button className="side-host-del" style={{ marginLeft: 'auto' }} onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {data.loading && <div className="muted">Running across all hosts…</div>}
          {(data.results || []).map((r) => (
            <div key={r.name} className="fleet-row">
              <div className="fleet-name"><span className={'dot' + (r.ok ? ' up' : ' down')} /> {r.name}</div>
              {r.output && <pre className="fleet-out">{r.output}</pre>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function ConnectController({ onCancel, onSave }) {
  const [f, setF] = useState({ base_url: '', username: '', password: '', totp_code: '', api_key: '' })
  const [useKey, setUseKey] = useState(false)
  const set = (k, v) => setF((s) => ({ ...s, [k]: v }))
  return (
    <div className="add-host">
      <input placeholder="Controller URL (https://host:9000)" value={f.base_url} onChange={(e) => set('base_url', e.target.value)} autoFocus />
      {useKey ? (
        <input placeholder="Backend API key" type="password" value={f.api_key} onChange={(e) => set('api_key', e.target.value)} />
      ) : (
        <>
          <input placeholder="Username" value={f.username} onChange={(e) => set('username', e.target.value)} />
          <input placeholder="Password" type="password" value={f.password} onChange={(e) => set('password', e.target.value)} />
          <input placeholder="MFA code (if enabled)" value={f.totp_code} onChange={(e) => set('totp_code', e.target.value)} />
        </>
      )}
      <button className="link" style={{ background: 'none', border: 0, padding: 0, textAlign: 'left', cursor: 'pointer', fontSize: 12 }}
        onClick={() => setUseKey((v) => !v)}>{useKey ? 'Use username & password instead' : 'Use a backend API key instead'}</button>
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button className="side-btn ghost" onClick={onCancel}>Cancel</button>
        <button className="side-btn" onClick={() => onSave(useKey ? { base_url: f.base_url, api_key: f.api_key } : { base_url: f.base_url, username: f.username, password: f.password, totp_code: f.totp_code })}>Connect &amp; sync</button>
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
