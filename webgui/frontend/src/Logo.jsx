import React from 'react'

// The Sysible Connect mark — same family as the Controller (spoked topology) and
// SLEP (code-bracket + run-triangle) marks: a dark rounded tile with the brand
// green ring. Connect's own glyph is a terminal prompt — a green chevron "❯" and a
// blinking blue cursor block — since Connect is the fleet's terminal workspace.
// Inlined so it stays crisp at any size and needs no network.
export default function Logo({ size = 34 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" role="img" aria-label="Sysible Connect"
      style={{ display: 'block', borderRadius: size * 0.22 }}>
      <defs>
        <linearGradient id="cn-tile" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#161d29" />
          <stop offset="1" stopColor="#0a0d13" />
        </linearGradient>
      </defs>
      <rect x="6" y="6" width="116" height="116" rx="28" ry="28" fill="url(#cn-tile)" />
      <rect x="8.5" y="8.5" width="111" height="111" rx="25.5" ry="25.5" fill="none" stroke="#6ddb73" strokeWidth="4" />
      {/* prompt chevron ❯ */}
      <path d="M40 44 L64 64 L40 84" fill="none" stroke="#6ddb73" strokeWidth="9"
        strokeLinecap="round" strokeLinejoin="round" />
      {/* cursor block */}
      <rect x="72" y="74" width="20" height="10" rx="2" fill="#7aa2ff" />
    </svg>
  )
}
