import React, { useEffect, useImperativeHandle, useRef, useState, forwardRef } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { terminalWsUrl } from './api.js'

// One independent terminal: its own xterm + websocket to a local shell, an SSH
// host, or a Controller-proxied host. Kept mounted across layout changes (the
// workspace positions tiles by CSS, never remounts them), so a split/resize/tab-
// switch never drops the session. Carries its own toolbar: Ctrl+C, font size,
// find-in-output, and save-output.
const Terminal = forwardRef(function Terminal({ spec, onStatus }, ref) {
  const elRef = useRef(null)
  const termRef = useRef(null)
  const fitRef = useRef(null)
  const searchRef = useRef(null)
  const wsRef = useRef(null)
  const [fontSize, setFontSize] = useState(13)
  const [findOpen, setFindOpen] = useState(false)
  const [findQ, setFindQ] = useState('')

  const sendInput = (d) => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'i', d }))
  }
  const bumpFont = (delta) => setFontSize((s) => Math.min(28, Math.max(8, s + delta)))
  const find = (prev) => { const s = searchRef.current; if (s && findQ) prev ? s.findPrevious(findQ) : s.findNext(findQ) }
  const saveOutput = () => {
    const term = termRef.current; if (!term) return
    const buf = term.buffer.active
    const lines = []
    for (let i = 0; i < buf.length; i++) lines.push(buf.getLine(i)?.translateToString(true) ?? '')
    const blob = new Blob([lines.join('\n').replace(/\s+$/, '') + '\n'], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${(spec.title || spec.host || 'terminal').replace(/[^\w.-]+/g, '_')}.log`
    document.body.appendChild(a); a.click(); a.remove()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }

  useImperativeHandle(ref, () => ({
    focus() { try { termRef.current?.focus() } catch { /* */ } },
    fit() { try { fitRef.current?.fit() } catch { /* */ } },
    clear() { termRef.current?.clear() },
  }))

  // Apply font-size changes live, then refit so the grid matches the new metrics.
  useEffect(() => {
    const term = termRef.current, fit = fitRef.current
    if (!term) return
    term.options.fontSize = fontSize
    try { fit.fit() } catch { /* */ }
  }, [fontSize])

  useEffect(() => {
    const term = new XTerm({
      fontSize, cursorBlink: true, scrollback: 8000, allowProposedApi: true,
      theme: { background: '#0b0f17', foreground: '#e9f0f7', cursor: '#6ddb73' },
    })
    const fit = new FitAddon(); term.loadAddon(fit)
    const search = new SearchAddon(); term.loadAddon(search)
    termRef.current = term; fitRef.current = fit; searchRef.current = search
    term.open(elRef.current)
    try { fit.fit() } catch { /* not laid out yet */ }

    let closed = false
    const ws = new WebSocket(terminalWsUrl({ kind: spec.kind, host: spec.host, cols: term.cols, rows: term.rows }))
    wsRef.current = ws
    const send = (o) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(o)) }
    ws.onopen = () => { onStatus?.('open'); term.focus(); send({ t: 'r', cols: term.cols, rows: term.rows }) }
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data)
      if (m.t === 'o') term.write(m.d)
      else if (m.t === 'exit') { term.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n'); onStatus?.('exited') }
      else if (m.t === 'error') { term.write(`\r\n\x1b[31m${m.d}\x1b[0m\r\n`); onStatus?.('error') }
    }
    ws.onclose = () => { if (!closed) onStatus?.('closed') }

    const dataSub = term.onData((d) => send({ t: 'i', d }))
    const resizeSub = term.onResize(({ cols, rows }) => send({ t: 'r', cols, rows }))
    const ro = new ResizeObserver(() => { try { fit.fit() } catch { /* */ } })
    ro.observe(elRef.current)

    return () => {
      closed = true
      dataSub.dispose(); resizeSub.dispose(); ro.disconnect()
      try { ws.close() } catch { /* */ }
      term.dispose()
    }
  }, [])   // connect once; spec is fixed for a tile's life

  return (
    <div className="term-wrap">
      <div className="term-tools">
        <button title="Send Ctrl+C" onClick={() => { sendInput('\x03'); termRef.current?.focus() }}>^C</button>
        <button title="Smaller font" onClick={() => bumpFont(-1)}>A−</button>
        <button title="Larger font" onClick={() => bumpFont(1)}>A+</button>
        <button title="Find in output" className={findOpen ? 'on' : ''} onClick={() => setFindOpen((v) => !v)}>⌕</button>
        <button title="Save output to a file" onClick={saveOutput}>⭳</button>
        {findOpen && (
          <span className="term-find">
            <input autoFocus placeholder="find…" value={findQ}
              onChange={(e) => setFindQ(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') find(e.shiftKey); if (e.key === 'Escape') setFindOpen(false) }} />
            <button title="Previous" onClick={() => find(true)}>↑</button>
            <button title="Next" onClick={() => find(false)}>↓</button>
          </span>
        )}
      </div>
      <div className="term" ref={elRef} onClick={() => termRef.current?.focus()} />
    </div>
  )
})

export default Terminal
