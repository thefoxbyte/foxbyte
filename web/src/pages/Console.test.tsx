// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The contract the end-to-end suite depends on.
//
// On 3 October a nightly failed four console tests at once. None of the four
// was a product bug: the tests were looking for a heading that a redesign had
// removed, a button renamed from "Run query" to "Run", and the first cell of a
// result row, which had become the JSON expander. Every one of them passed
// gofmt, go vet, go test, tsc and the production build, because the only thing
// that exercises the console is Playwright against a live stack, and that runs
// nightly.
//
// So these are not a second copy of the end-to-end tests. They assert the
// handful of things those tests reach for — the selectors and the accessible
// names — in a jsdom render that needs no stack and finishes in a second. If a
// rename or a restructure breaks the contract, it breaks here, on the pull
// request, with the reason attached.
import { render, screen, waitFor, fireEvent, cleanup, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { QueryResult } from '../api'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    getBranches: vi.fn(async () => [{ name: 'main', primary: true, agent: false, state: 'running', used: '1G', refer: '1G', connections: 1, port: '5432' }]),
    getAdmins: vi.fn(async () => ({ admins: ['a@b.c'], you: 'a@b.c', you_are_admin: true })),
    runQuery: vi.fn(async () => ({ columns: [], rows: [], command: 'SELECT 0' }) as QueryResult),
  }
})

import Console from './Console'
import { runQuery } from '../api'

const mockQuery = vi.mocked(runQuery)

// The schema rail asks for the table list on mount; everything else is a
// deliberate answer set by the test.
const SCHEMA: QueryResult = { columns: ['table_schema', 'table_name', 'table_type'], rows: [['public', 'invoices', 'BASE TABLE']], command: 'SELECT 1' }

// The branch's columns, which the console reads beside its table list for
// suggestions (point 9), are answered by what is asked rather than by turn, so
// the answers queued here still go to the statements a test runs.
let COLUMNS: QueryResult = { columns: [], rows: [], command: 'SELECT 0' }
function answer(...results: (QueryResult | Promise<QueryResult>)[]) {
  const queue = [SCHEMA, ...results]
  mockQuery.mockReset()
  mockQuery.mockImplementation(async (_branch: string, sql: string) => {
    if (sql.includes('pg_attribute')) return COLUMNS
    return queue.length ? queue.shift()! : { columns: [], rows: [], command: 'SELECT 0' }
  })
}

async function open() {
  render(<MemoryRouter><Console /></MemoryRouter>)
  await screen.findByRole('button', { name: /^run/i })
}

const editor = () => document.querySelector('textarea.editor') as HTMLTextAreaElement
const type = (sql: string) => fireEvent.change(editor(), { target: { value: sql } })
const run = () => fireEvent.click(screen.getByRole('button', { name: /^run/i }))

beforeEach(() => { COLUMNS = { columns: [], rows: [], command: 'SELECT 0' }; answer() })
afterEach(cleanup)

describe('what the end-to-end suite reaches for', () => {
  it('finds the editor, the Run button and a gutter line per line', async () => {
    await open()
    expect(editor()).toBeTruthy()
    // `getByRole(button, /^run/i)` is how the suite clicks it. The name was
    // "Run query" until the toolbar redesign, and the suite went on looking
    // for that for two weeks.
    expect(screen.getByRole('button', { name: /^run/i })).toBeTruthy()

    type('SELECT 1;\nSELECT 2;\nSELECT 3;')
    await waitFor(() => expect(document.querySelectorAll('.wb-gutter > div')).toHaveLength(3))
  })

  it('does not let the expander cell pass as the first value', async () => {
    answer({ columns: ['n'], rows: [['42']], command: 'SELECT 1' })
    await open()
    type('SELECT 42 AS n')
    run()
    await waitFor(() => expect(document.querySelectorAll('.res-body td').length).toBeGreaterThan(0))

    // Every row opens with a `{ }` button that expands it as JSON. A suite that
    // takes `.res-body td` first gets that button, compares it to a number and
    // fails in a way that reads like a product bug. It did, in two tests.
    expect(document.querySelector('.res-body td')!.textContent).toBe('{ }')
    expect(document.querySelector('.res-body td:not(.expand-col)')!.textContent).toBe('42')
  })

  it('gives a script one tab per statement', async () => {
    answer({
      results: [
        { command: 'CREATE TABLE' },
        { command: 'INSERT 0 2' },
        { columns: ['count'], rows: [['2']], command: 'SELECT 1' },
      ],
    } as QueryResult)
    await open()
    type('CREATE TABLE t (id int); INSERT INTO t VALUES (1),(2); SELECT count(*) FROM t;')
    run()
    await waitFor(() => expect(document.querySelectorAll('.res-tab')).toHaveLength(3))
  })

  it('stops taking edits while a query is in flight', async () => {
    let release: (r: QueryResult) => void = () => {}
    answer(new Promise<QueryResult>(r => { release = r }))
    await open()
    type('SELECT pg_sleep(2)')
    run()
    await waitFor(() => expect(editor().readOnly).toBe(true))
    release({ columns: [], rows: [], command: 'SELECT 0' })
    await waitFor(() => expect(editor().readOnly).toBe(false))
  })

  it('says nothing was applied even when only one statement completed', async () => {
    // The shape that hid the bug: a two-statement script failing on the second
    // comes back with ONE completed result, so it takes the single-result path.
    // The note lived only on the tabbed path, and the case where it matters
    // most — did my INSERT stick? — was the case that never showed it.
    answer({
      error: 'relation "no_such_table" does not exist',
      note: 'nothing was applied: Postgres runs a multi-statement script in one transaction unless the script opens its own',
      results: [{ command: 'INSERT 0 1' }],
    } as QueryResult)
    await open()
    type('INSERT INTO t VALUES (3); SELECT * FROM no_such_table;')
    run()
    await screen.findByText(/nothing was applied/i)
  })

  it('marks the line a syntax error is on', async () => {
    answer({ error: 'syntax error at or near "SELCT"', position: 21 } as QueryResult)
    await open()
    type('SELECT 1;\nSELECT 2;\nSELCT 3;\nSELECT 4;')
    run()
    await waitFor(() => {
      const bad = document.querySelectorAll('.wb-gutter .bad')
      expect(bad).toHaveLength(1)
      expect(bad[0].textContent).toBe('3')
    })
    expect(document.querySelector('.err-at')!.textContent).toMatch(/line 3/)
  })
})

// Point 9: suggestions in the editor, as the page wires them.
describe('query suggestions', () => {
  const invoices: QueryResult = {
    columns: ['nspname', 'relname', 'kind', 'attname', 'type', 'pk'],
    rows: [['public', 'invoices', 'table', 'id', 'integer', true], ['public', 'invoices', 'table', 'amount', 'numeric', false]],
    command: 'SELECT 2',
  }
  // Typing as a person does: the text so far, the caret at its end, and the
  // character just typed.
  // React keeps its own copy of the value, so a test sets it through the
  // element's native setter, as typing does, before the input event.
  const setNative = (ed: HTMLTextAreaElement, v: string) =>
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(ed, v)
  const typeChar = (before: string, ch: string) => {
    const ed = editor()
    setNative(ed, before + ch)
    ed.setSelectionRange(ed.value.length, ed.value.length)
    ed.dispatchEvent(new InputEvent('input', { bubbles: true, data: ch, inputType: 'insertText' }))
  }

  it('offers the table after FROM and its columns after the alias, and Enter takes one', async () => {
    COLUMNS = invoices
    answer()
    await open()
    await waitFor(() => expect(mockQuery.mock.calls.some(c => String(c[1]).includes('pg_attribute'))).toBe(true))
    typeChar('SELECT * FROM in', 'v')
    const list = await screen.findByRole('listbox', { name: 'Suggestions' })
    expect(within(list).getAllByRole('option').map(o => o.textContent)).toEqual(['tinvoicestable'])
    fireEvent.keyDown(editor(), { key: 'Enter' })
    expect(editor().value).toBe('SELECT * FROM invoices')
    expect(screen.queryByRole('listbox')).toBeNull()

    typeChar('SELECT i', '.')
    // Nothing named i: no columns, and nothing offered.
    expect(screen.queryByRole('listbox')).toBeNull()
    setNative(editor(), 'SELECT i. FROM invoices i')
    fireEvent.change(editor(), { target: { value: 'SELECT i. FROM invoices i' } })
    editor().setSelectionRange(9, 9)
    fireEvent.keyDown(editor(), { key: ' ', ctrlKey: true })
    const cols = await screen.findByRole('listbox', { name: 'Suggestions' })
    expect(within(cols).getAllByRole('option').map(o => o.querySelector('.l')?.textContent)).toEqual(['id', 'amount'])
    fireEvent.keyDown(editor(), { key: 'ArrowDown' })
    fireEvent.keyDown(editor(), { key: 'Tab' })
    expect(editor().value).toBe('SELECT i.amount FROM invoices i')
  })

  it('Escape closes the list, and ⌘↵ still runs', async () => {
    COLUMNS = invoices
    answer({ columns: ['n'], rows: [[1]], command: 'SELECT 1' })
    await open()
    await waitFor(() => expect(mockQuery.mock.calls.some(c => String(c[1]).includes('pg_attribute'))).toBe(true))
    fireEvent.change(editor(), { target: { value: 'SELECT * FROM ' } })
    editor().setSelectionRange(14, 14)
    fireEvent.keyDown(editor(), { key: ' ', ctrlKey: true })
    await screen.findByRole('listbox', { name: 'Suggestions' })
    fireEvent.keyDown(editor(), { key: 'Escape' })
    expect(screen.queryByRole('listbox')).toBeNull()
    type('SELECT 1')
    fireEvent.keyDown(editor(), { key: 'Enter', metaKey: true })
    await waitFor(() => expect(mockQuery.mock.calls.some(c => c[1] === 'SELECT 1')).toBe(true))
  })

  it('offers "did you mean" under an error, and fixes it where Postgres pointed', async () => {
    answer(
      { error: 'relation "invoces" does not exist', position: 15, suggestion: { kind: 'table', wrong: 'invoces', right: 'invoices', insert: 'invoices' } },
      { columns: ['n'], rows: [[3]], command: 'SELECT 1' },
    )
    await open()
    type('SELECT * FROM invoces')
    run()
    expect(await screen.findByText(/did you mean/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Fix and run' }))
    expect(editor().value).toBe('SELECT * FROM invoices')
    await waitFor(() => expect(mockQuery.mock.calls.some(c => c[1] === 'SELECT * FROM invoices')).toBe(true))
  })

  it('puts a table\'s snippet in the editor', async () => {
    COLUMNS = invoices
    answer()
    await open()
    await waitFor(() => expect(mockQuery.mock.calls.some(c => String(c[1]).includes('pg_attribute'))).toBe(true))
    fireEvent.click(await screen.findByRole('button', { name: /invoices/ }))
    fireEvent.click(await screen.findByRole('button', { name: /snippets/i }))
    const menu = screen.getByRole('menu', { name: 'Snippets for invoices' })
    expect(within(menu).getAllByRole('menuitem').map(m => m.textContent)).toEqual(['Select rows', 'Count rows', 'Insert a row', 'Update a row', 'Delete a row'])
    fireEvent.click(within(menu).getByRole('menuitem', { name: 'Delete a row' }))
    expect(editor().value).toBe('DELETE FROM invoices\nWHERE id = NULL;')
  })
})
