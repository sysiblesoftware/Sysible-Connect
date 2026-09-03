// Pane-layout model tests, run with plain node (no test runner dependency):
//   node webgui/frontend/test/layout.test.mjs
//
// These cover the gap behind "there's no real way to make vertical terminals":
// the tree always supported 'col', but every new pane was appended to the RIGHT of
// the active one, so two DIFFERENT hosts could never be stacked. splitLeaf gained
// `before`, and dropTarget resolves a point over the stage to the pane and edge a
// dragged host should split.
import { leaf, splitLeaf, closeLeaf, layout, dropTarget } from '../src/layout.js'

let failed = 0
const eq = (got, want, what) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { failed++; console.log(`FAIL  ${what}\n      got  ${g}\n      want ${w}`) }
  else console.log(`ok    ${what}`)
}
const ok = (cond, what) => { if (!cond) { failed++; console.log(`FAIL  ${what}`) } else console.log(`ok    ${what}`) }

// ---- splitting in both directions, both orders ---------------------------
const a = leaf({ title: 'deb-web-1' })
const b = leaf({ title: 'rocky-web-1' })

const right = splitLeaf(a, a.id, 'row', b)
eq(layout(right).tiles.map((t) => t.spec.title), ['deb-web-1', 'rocky-web-1'], 'split row appends to the right')

const below = splitLeaf(a, a.id, 'col', b)
const belowTiles = layout(below).tiles
eq(belowTiles.map((t) => t.spec.title), ['deb-web-1', 'rocky-web-1'], 'split col keeps document order')
ok(belowTiles[0].rect.left === belowTiles[1].rect.left, 'stacked panes share a left edge')
ok(belowTiles[1].rect.top > belowTiles[0].rect.top, 'the second pane sits BELOW the first')
ok(belowTiles[0].rect.w === 100, 'a stacked pane spans the full width')

const above = splitLeaf(a, a.id, 'col', b, true)
const aboveTiles = layout(above).tiles
eq(aboveTiles.map((t) => t.spec.title), ['rocky-web-1', 'deb-web-1'], 'before=true puts the new pane ABOVE')
ok(aboveTiles[0].rect.top < aboveTiles[1].rect.top, 'and it really is drawn first')

const leftOf = splitLeaf(a, a.id, 'row', b, true)
eq(layout(leftOf).tiles.map((t) => t.spec.title), ['rocky-web-1', 'deb-web-1'], 'before=true puts the new pane LEFT')

// ---- the drop target: every point resolves to a direction ----------------
const single = leaf({ title: 'only' })
eq(dropTarget(single, 50, 8), { id: single.id, dir: 'col', before: true,
   rect: { left: 0, top: 0, w: 100, h: 50 } }, 'near the top edge -> stack above')
const bottom = dropTarget(single, 50, 92)
eq({ dir: bottom.dir, before: bottom.before }, { dir: 'col', before: false }, 'near the bottom edge -> stack below')
const l = dropTarget(single, 4, 50)
eq({ dir: l.dir, before: l.before }, { dir: 'row', before: true }, 'near the left edge -> split left')
const r = dropTarget(single, 96, 50)
eq({ dir: r.dir, before: r.before }, { dir: 'row', before: false }, 'near the right edge -> split right')
ok(dropTarget(single, 50, 50) !== null, 'the centre still resolves — no dead zone that silently drops nothing')
ok(dropTarget(null, 50, 50) === null, 'an empty workspace has no tile to target')

// ---- it picks the RIGHT pane in a multi-pane workspace -------------------
const two = splitLeaf(a, a.id, 'row', b)          // deb | rocky
const onRocky = dropTarget(two, 75, 90)
eq({ id: onRocky.id === b.id, dir: onRocky.dir, before: onRocky.before },
   { id: true, dir: 'col', before: false }, 'a drop on the right pane\'s bottom targets THAT pane')
const onDeb = dropTarget(two, 25, 10)
eq({ id: onDeb.id === a.id, dir: onDeb.dir }, { id: true, dir: 'col' },
   'a drop on the left pane\'s top targets the left pane')

// the preview rect must be the half that pane will give up, not the whole stage
ok(onRocky.rect.left === 50 && onRocky.rect.w === 50 && onRocky.rect.h === 50,
   'the preview covers exactly the half the new pane takes')

// ---- three different hosts, stacked — the thing that was impossible ------
const c = leaf({ title: 'ubuntu-web-1' })
let tree = splitLeaf(a, a.id, 'col', b)           // deb over rocky
tree = splitLeaf(tree, b.id, 'col', c)            // ...over ubuntu
const three = layout(tree).tiles
eq(three.map((t) => t.spec.title), ['deb-web-1', 'rocky-web-1', 'ubuntu-web-1'], 'three DIFFERENT hosts stack')
ok(three.every((t) => t.rect.left === 0 && t.rect.w === 100), 'all full-width')
ok(three[0].rect.top < three[1].rect.top && three[1].rect.top < three[2].rect.top, 'in top-to-bottom order')

// ---- closing still promotes the sibling ---------------------------------
const afterClose = closeLeaf(tree, b.id)
eq(layout(afterClose).tiles.map((t) => t.spec.title), ['deb-web-1', 'ubuntu-web-1'], 'closing the middle promotes the rest')
ok(closeLeaf(leaf({ title: 'x' }), 'nope') !== null, 'closing an unknown id leaves the tree alone')

console.log(failed ? `\n${failed} FAILED` : '\nall passed')
process.exit(failed ? 1 : 0)
