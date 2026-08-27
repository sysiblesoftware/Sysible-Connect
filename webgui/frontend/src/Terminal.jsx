import React, { useEffect, useImperativeHandle, useRef, forwardRef } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { terminalWsUrl } from './api.js'

// One independent terminal: its own xterm + websocket to a local shell or an SSH
// host. Kept mounted across layout changes (the workspace positions tiles by CSS,
// never remounts them), so a split/resize/tab-switch never drops the session.
const Terminal = forwardRef(function Terminal({ spec, onStatus }, ref) {
  const elRef = useRef(null)
  const termRef = useRef(null)
  const fitRef = useRef(null)
  const searchRef = useRef(null)
  const wsRef = useRef(null)

  useImperativeHandle(ref, () => ({
    focus() { try { termRef.current?.focus() } catch { /* */ } },
    fit() { try { fitRef.current?.fit() } catch { /* */ } },
    find(q, prev) { const s = searchRef.current; if (s && q) prev ? s.findPrevious(q) : s.findNext(q) },
    clear() { termRef.current?.clear() },
  }))

  useEffect(() => {
    const term = new XTerm({
      fontSize: 13, cursorBlink: true, scrollback: 8000, allowProposedApi: true,
      theme: { background: '#0b0f17', foreground: '#d5deee', cursor: '#63c869' },
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

  return <div className="term" ref={elRef} onClick={() => termRef.current?.focus()} />
})

export default Terminal
