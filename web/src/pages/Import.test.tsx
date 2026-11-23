// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    importFileStream: vi.fn(),
    importDBStream: vi.fn(),
    listReplication: vi.fn(async () => []),
    cutoverReplication: vi.fn(),
  }
})

import { importFileStream } from '../api'
import { ConfirmProvider } from '../confirm'
import Import from './Import'

function page() {
  render(<MemoryRouter><ConfirmProvider><Import /></ConfirmProvider></MemoryRouter>)
}

// "From a file" is the licence upload's drop box: the whole box chooses a file,
// a dropped file is taken the same way, and the file chosen is named in it.
describe('Import: from a file', () => {
  beforeEach(() => {
    // jsdom has no scrolling; the page scrolls its live log to the end.
    Element.prototype.scrollTo = vi.fn() as unknown as typeof Element.prototype.scrollTo
    vi.mocked(importFileStream).mockReset().mockResolvedValue(undefined as never)
  })
  afterEach(cleanup)

  it('names the file chosen in the drop box and lets it be migrated', async () => {
    page()
    const box = screen.getByTestId('import-file')
    expect(box.textContent).toMatch(/Choose a file.*or drop it here/)
    const upload = screen.getByText('Upload & migrate').closest('button')!
    expect(upload.disabled).toBe(true)
    const f = new File(['select 1;'], 'dump.sql', { type: 'application/sql' })
    fireEvent.change(screen.getByLabelText('File to migrate'), { target: { files: [f] } })
    expect(box.textContent).toMatch(/dump\.sql.*9 bytes.*choose another/)
    expect(box.className).toContain('has-file')
    expect(upload.disabled).toBe(false)
    fireEvent.click(upload)
    await waitFor(() => expect(importFileStream).toHaveBeenCalledWith(f, '', expect.any(Function)))
  })

  it('takes a file dropped on the box', () => {
    page()
    const box = screen.getByTestId('import-file')
    const f = new File(['a,b\n1,2\n'], 'rows.csv', { type: 'text/csv' })
    fireEvent.dragOver(box, { dataTransfer: { files: [f] } })
    expect(box.className).toContain('dragging')
    fireEvent.drop(box, { dataTransfer: { files: [f] } })
    expect(box.className).not.toContain('dragging')
    expect(box.textContent).toMatch(/rows\.csv/)
  })
})
