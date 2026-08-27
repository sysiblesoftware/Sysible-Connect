// A workspace is a binary tree of panes: a `leaf` (one terminal) or a `split`
// (two children side-by-side `row` or stacked `col`, at `ratio`). Terminals are
// rendered from the FLATTENED leaf list and positioned by CSS rect, so splitting,
// resizing or switching workspaces never remounts a terminal (its session lives on).
let _id = 1
export const nid = () => 'n' + (_id++)
export const leaf = (spec) => ({ id: nid(), t: 'leaf', spec })
export const isLeaf = (n) => !!n && n.t === 'leaf'

// Replace `leafId` with a split of [that leaf, newLeafNode] in direction dir.
export function splitLeaf(node, leafId, dir, newLeafNode) {
  if (isLeaf(node)) {
    if (node.id !== leafId) return node
    return { id: nid(), t: 'split', dir, ratio: 0.5, a: node, b: newLeafNode }
  }
  return { ...node, a: splitLeaf(node.a, leafId, dir, newLeafNode), b: splitLeaf(node.b, leafId, dir, newLeafNode) }
}

// Remove a leaf; promote its sibling. Returns the new tree, or null if it was the last.
export function closeLeaf(node, leafId) {
  if (isLeaf(node)) return node.id === leafId ? null : node
  const a = closeLeaf(node.a, leafId)
  const b = closeLeaf(node.b, leafId)
  if (a === null) return b
  if (b === null) return a
  return { ...node, a, b }
}

export function setRatio(node, splitId, ratio) {
  if (isLeaf(node)) return node
  const r = Math.min(0.9, Math.max(0.1, ratio))
  if (node.id === splitId) return { ...node, ratio: r }
  return { ...node, a: setRatio(node.a, splitId, ratio), b: setRatio(node.b, splitId, ratio) }
}

export function firstLeafId(node) { return isLeaf(node) ? node.id : firstLeafId(node.a) }

// Absolute rects (%) for every leaf + the draggable dividers, from a % rect.
export function layout(node, rect = { left: 0, top: 0, w: 100, h: 100 }) {
  if (isLeaf(node)) return { tiles: [{ id: node.id, spec: node.spec, rect }], dividers: [] }
  const T = 0.5   // divider thickness in % (CSS pads the hit area)
  let aRect, bRect, div
  if (node.dir === 'row') {
    const aw = rect.w * node.ratio
    aRect = { left: rect.left, top: rect.top, w: aw, h: rect.h }
    bRect = { left: rect.left + aw, top: rect.top, w: rect.w - aw, h: rect.h }
    div = { id: node.id, dir: 'row', split: rect, rect: { left: rect.left + aw - T / 2, top: rect.top, w: T, h: rect.h } }
  } else {
    const ah = rect.h * node.ratio
    aRect = { left: rect.left, top: rect.top, w: rect.w, h: ah }
    bRect = { left: rect.left, top: rect.top + ah, w: rect.w, h: rect.h - ah }
    div = { id: node.id, dir: 'col', split: rect, rect: { left: rect.left, top: rect.top + ah - T / 2, w: rect.w, h: T } }
  }
  const A = layout(node.a, aRect)
  const B = layout(node.b, bRect)
  return { tiles: [...A.tiles, ...B.tiles], dividers: [div, ...A.dividers, ...B.dividers] }
}
