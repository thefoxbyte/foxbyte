// SPDX-License-Identifier: AGPL-3.0-or-later
import { useCallback, useRef, useState, type KeyboardEvent, type RefObject } from 'react'
import { complete, type Completion, type Rel } from '../sqlcomplete'

// Autocomplete in the SQL editor (point 9.1). The rules of what to offer are in
// sqlcomplete.ts; this is the part that lives in the page: when the list opens,
// where it sits, and the keys.
//
//   - It opens as you type a name (or a dot after one), and after FROM, JOIN,
//     INTO and UPDATE; Ctrl+Space opens it anywhere.
//   - ↑ ↓ choose, Enter or Tab take the choice, Esc closes it; ⌘/Ctrl+Enter
//     still runs the query, and typing goes on as usual.
//   - It never opens inside a string or a comment.

const TABLE_WORD = /\b(from|join|into|update)\s$/i

// caretXY is where a character sits inside a textarea, by laying the same text
// out in a hidden copy with the same font and measuring a marker at that spot.
function caretXY(el: HTMLTextAreaElement, pos: number): { x: number; y: number; h: number } {
  const cs = getComputedStyle(el)
  const div = document.createElement('div')
  for (const p of ['fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'paddingTop', 'paddingLeft',
    'paddingRight', 'paddingBottom', 'borderTopWidth', 'borderLeftWidth', 'tabSize', 'whiteSpace', 'wordWrap'] as const) {
    (div.style as unknown as Record<string, string>)[p] = (cs as unknown as Record<string, string>)[p]
  }
  Object.assign(div.style, { position: 'absolute', visibility: 'hidden', top: '0', left: '0', whiteSpace: 'pre', width: cs.width })
  div.textContent = el.value.slice(0, pos)
  const mark = document.createElement('span')
  mark.textContent = '​'
  div.appendChild(mark)
  document.body.appendChild(div)
  // Relative to the textarea's parent, which holds the line numbers beside it.
  const out = { x: el.offsetLeft + mark.offsetLeft - el.scrollLeft, y: el.offsetTop + mark.offsetTop - el.scrollTop, h: parseFloat(cs.lineHeight) || 18 }
  div.remove()
  return out
}

type Open = Completion & { sel: number; x: number; y: number }

export function useCompletion({ editor, text, setText, schema, busy }: {
  editor: RefObject<HTMLTextAreaElement | null>
  text: string
  setText: (s: string) => void
  schema: Rel[]
  busy: boolean
}) {
  const [open, setOpen] = useState<Open | null>(null)
  const listId = useRef(`sql-complete-${Math.random().toString(36).slice(2)}`).current

  const show = useCallback((value: string, caret: number, force: boolean) => {
    const el = editor.current
    const c = el ? complete(value, caret, schema) : null
    if (!el || !c || c.items.length === 0) { setOpen(null); return }
    // Without a word started, only where a name is plainly next: after a dot,
    // after FROM and the like, or when asked.
    const typed = c.to - c.from
    if (!force && typed === 0 && value[c.from - 1] !== '.' && !TABLE_WORD.test(value.slice(0, c.from))) { setOpen(null); return }
    if (!force && typed > 0 && c.items.length === 1 && c.items[0].insert === value.slice(c.from, c.to)) { setOpen(null); return }
    const p = caretXY(el, c.from)
    setOpen({ ...c, sel: 0, x: p.x, y: p.y + p.h })
  }, [editor, schema])

  const accept = useCallback((i: number) => {
    if (!open) return
    const it = open.items[i]
    const next = text.slice(0, open.from) + it.insert + text.slice(open.to)
    setText(next)
    setOpen(null)
    const at = open.from + it.insert.length
    requestAnimationFrame(() => { const el = editor.current; if (el) { el.focus(); el.setSelectionRange(at, at) } })
  }, [open, text, setText, editor])

  /** onChange follows the editor's own: decide after each edit whether to offer names. */
  const onChange = useCallback((value: string, caret: number, inserted: string | null) => {
    if (busy) return
    if (inserted !== null && /^[\w$.]$|^ $/.test(inserted)) show(value, caret, false)
    else setOpen(null)
  }, [busy, show])

  /** onKeyDown returns true when it used the key. */
  const onKeyDown = useCallback((e: KeyboardEvent<HTMLTextAreaElement>): boolean => {
    if (e.key === ' ' && e.ctrlKey) {
      e.preventDefault()
      show(e.currentTarget.value, e.currentTarget.selectionStart, true)
      return true
    }
    if (!open) return false
    if (e.metaKey || e.ctrlKey) { setOpen(null); return false } // ⌘↵ and friends keep their meaning
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); setOpen({ ...open, sel: (open.sel + 1) % open.items.length }); return true
      case 'ArrowUp': e.preventDefault(); setOpen({ ...open, sel: (open.sel - 1 + open.items.length) % open.items.length }); return true
      case 'Enter': case 'Tab': e.preventDefault(); accept(open.sel); return true
      case 'Escape': e.preventDefault(); e.stopPropagation(); setOpen(null); return true
      case 'ArrowLeft': case 'ArrowRight': case 'Home': case 'End': case 'PageUp': case 'PageDown': setOpen(null); return false
    }
    return false
  }, [open, accept, show])

  const close = useCallback(() => setOpen(null), [])

  const popup = open && (
    <ul id={listId} className="sql-complete" role="listbox" aria-label="Suggestions"
      style={{ left: Math.max(0, open.x), top: open.y }}
      // A click must not blur the editor before it is read.
      onMouseDown={e => e.preventDefault()}>
      {open.items.map((it, i) => (
        <li key={it.kind + it.label} id={`${listId}-${i}`} role="option" aria-selected={i === open.sel}
          className={i === open.sel ? 'on' : ''} onMouseEnter={() => setOpen({ ...open, sel: i })} onClick={() => accept(i)}>
          <span className={'k ' + it.kind}>{it.kind === 'column' ? 'c' : it.kind === 'table' ? 't' : it.kind === 'schema' ? 's' : 'k'}</span>
          <span className="l">{it.label}</span>
          {it.detail && <span className="d">{it.detail}</span>}
        </li>
      ))}
    </ul>
  )

  const aria = {
    'aria-autocomplete': 'list' as const,
    'aria-expanded': !!open,
    'aria-controls': open ? listId : undefined,
    'aria-activedescendant': open ? `${listId}-${open.sel}` : undefined,
  }
  return { onChange, onKeyDown, close, popup, aria, isOpen: !!open }
}
