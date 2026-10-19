// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ExportMenu, { exportFile, fileName } from './ExportMenu'

const cols = ['id', 'f']
const rows = [[1, '=1+1'], [2, null]]

describe('ExportMenu', () => {
  let blobs: Blob[]
  beforeEach(() => {
    localStorage.clear()
    blobs = []
    URL.createObjectURL = vi.fn((b: Blob) => { blobs.push(b); return 'blob:x' })
    URL.revokeObjectURL = vi.fn()
  })
  afterEach(cleanup)

  it('downloads CSV by default, spreadsheet-safe, named after the table', async () => {
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    render(<ExportMenu cols={cols} rows={rows} selected={0} sql="SELECT * FROM public.orders" />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    fireEvent.click(screen.getByRole('button', { name: /download all 2 rows/i }))
    expect(click).toHaveBeenCalled()
    expect(await blobs[0].text()).toBe("id,f\n1,'=1+1\n2,\n")
    expect(screen.getByText(/saved orders-\d{8}-\d{4}\.csv/i)).toBeTruthy()
    click.mockRestore()
  })

  it('exports the ticked rows only, and remembers the format', async () => {
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    render(<ExportMenu cols={cols} rows={[rows[1]]} selected={1} />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    fireEvent.change(screen.getByLabelText('Export format'), { target: { value: 'json' } })
    fireEvent.click(screen.getByRole('button', { name: /download 1 selected row$/i }))
    expect(JSON.parse(await blobs[0].text())).toEqual([{ id: 2, f: null }])
    expect(JSON.parse(localStorage.getItem('fox.export') ?? '{}').format).toBe('json')
    click.mockRestore()
  })
})

describe('ExportMenu: everything the query returns (1.3)', () => {
  let blobs: Blob[]
  let click: ReturnType<typeof vi.spyOn>
  beforeEach(() => {
    localStorage.clear()
    blobs = []
    URL.createObjectURL = vi.fn((b: Blob) => { blobs.push(b); return 'blob:x' })
    URL.revokeObjectURL = vi.fn()
    click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })
  afterEach(() => { cleanup(); click.mockRestore(); vi.unstubAllGlobals() })

  it('asks the server for every row, as the user, on the branch the result came from', async () => {
    const fetch = vi.fn(async () => new Response('id\n1\n2\n3\n', { status: 200 }))
    vi.stubGlobal('fetch', fetch)
    render(<ExportMenu cols={cols} rows={rows} selected={0} sql="SELECT * FROM events" branch="dev" />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    fireEvent.click(screen.getByLabelText(/everything the query returns/i))
    fireEvent.click(screen.getByRole('button', { name: /download every row/i }))
    await waitFor(() => expect(screen.getByText(/saved events-\d{8}-\d{4}\.csv/i)).toBeTruthy())
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/\/api\/branches\/dev\/export$/)
    expect(init.credentials).toBe('include')
    expect(JSON.parse(init.body as string)).toEqual({ sql: 'SELECT * FROM events', format: 'csv', safe: true })
    expect(await blobs[0].text()).toBe('id\n1\n2\n3\n')
  })

  it('shows the error when the statement is refused, and saves nothing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'cannot execute UPDATE in a read-only transaction' }), { status: 400 })))
    render(<ExportMenu cols={cols} rows={rows} selected={0} sql="UPDATE t SET a=1 RETURNING *" branch="main" />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    fireEvent.click(screen.getByLabelText(/everything the query returns/i))
    fireEvent.click(screen.getByRole('button', { name: /download every row/i }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/read-only transaction/)
    expect(blobs).toHaveLength(0)
  })

  it('is not offered without a branch, and a script says to run the statement alone', () => {
    render(<ExportMenu cols={cols} rows={rows} selected={0} sql="SELECT 1" />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    expect(screen.queryByLabelText(/everything the query returns/i)).toBeNull()
    cleanup()
    render(<ExportMenu cols={cols} rows={rows} selected={0} sql="SELECT 1; SELECT 2" branch="main" script />)
    fireEvent.click(screen.getByRole('button', { name: /export ▾/i }))
    expect(screen.queryByLabelText(/everything the query returns/i)).toBeNull()
    expect(screen.getByText(/run the statement on its own/i)).toBeTruthy()
  })
})

describe('exportFile and fileName', () => {
  it('builds a workbook for Excel', async () => {
    const b = exportFile(cols, rows, 'xlsx', true)
    expect(b.type).toContain('spreadsheetml')
    const bytes = new Uint8Array(await b.arrayBuffer())
    expect([...bytes.slice(0, 4)]).toEqual([0x50, 0x4b, 0x03, 0x04]) // a zip
  })
  it('can leave a formula as it is', async () => {
    expect(await exportFile(cols, rows, 'csv', false).text()).toBe('id,f\n1,=1+1\n2,\n')
  })
  it('names a file after the table and the minute', () => {
    const at = new Date(2026, 9, 17, 14, 5)
    expect(fileName('select * from "Sales Q3"', 'csv', at)).toBe('Sales_Q3-20261017-1405.csv')
    expect(fileName('select 1', 'xlsx', at)).toBe('result-20261017-1405.xlsx')
    expect(fileName('SELECT * FROM public.orders o', 'json', at)).toBe('orders-20261017-1405.json')
  })
})
