import React from 'react'

// Inline SVG icons. We draw these ourselves instead of using Unicode glyphs
// (⭳ ⌕ ◫ ⊟ ⇱ …) because those depend on a font that carries them — on the
// Sysible Workstation console font several rendered as garbled "tofu" boxes.
// SVG paths render identically everywhere and inherit the button's currentColor.
const svg = (children, vb = '0 0 16 16') => (props) => (
  <svg viewBox={vb} width="14" height="14" fill="none" stroke="currentColor"
    strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
    aria-hidden="true" focusable="false" {...props}>{children}</svg>
)

// find-in-output: a magnifier
export const IconSearch = svg(<><circle cx="7" cy="7" r="4.2" /><line x1="10.2" y1="10.2" x2="14" y2="14" /></>)
// save output to a file: a tray with a down arrow (download-to-disk)
export const IconSave = svg(<><path d="M8 2v7" /><path d="M5 6.5 8 9.5 11 6.5" /><path d="M3 11.5v1.5a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1.5" /></>)
// split into a new pane on the right (vertical divider)
export const IconSplitRight = svg(<><rect x="2" y="3" width="12" height="10" rx="1.2" /><line x1="8" y1="3" x2="8" y2="13" /></>)
// split into a new pane below (horizontal divider)
export const IconSplitDown = svg(<><rect x="2" y="3" width="12" height="10" rx="1.2" /><line x1="2" y1="8" x2="14" y2="8" /></>)
// pop the pane out into its own window
export const IconPopout = svg(<><path d="M9 3h4v4" /><path d="M13 3 8 8" /><path d="M12 9.5V12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h2.5" /></>)
// close / exit
export const IconClose = svg(<><line x1="4" y1="4" x2="12" y2="12" /><line x1="12" y1="4" x2="4" y2="12" /></>)
// theme: sun (shown in dark mode — click for light) and moon (shown in light mode)
export const IconSun = svg(<><circle cx="8" cy="8" r="3.2" /><line x1="8" y1="1.5" x2="8" y2="3" /><line x1="8" y1="13" x2="8" y2="14.5" /><line x1="1.5" y1="8" x2="3" y2="8" /><line x1="13" y1="8" x2="14.5" y2="8" /><line x1="3.4" y1="3.4" x2="4.5" y2="4.5" /><line x1="11.5" y1="11.5" x2="12.6" y2="12.6" /><line x1="12.6" y1="3.4" x2="11.5" y2="4.5" /><line x1="4.5" y1="11.5" x2="3.4" y2="12.6" /></>)
export const IconMoon = svg(<path d="M13 9.5A5.2 5.2 0 0 1 6.5 3a5.3 5.3 0 1 0 6.5 6.5Z" />)
