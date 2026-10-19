// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EditGrid, FilterBar, type ColInfo } from './DataGrid'
import type { Filter } from '../gridquery'

afterEach(cleanup)

describe('FilterBar', () => {
  it('adds a filter, shows it as a chip, and removes it', () => {
    const onChange = vi.fn()
    const { rerender } = render(<FilterBar cols={['id', 'name']} filters={[]} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('Filter column'), { target: { value: 'name' } })
    fireEvent.change(screen.getByLabelText('Filter comparison'), { target: { value: 'contains' } })
    fireEvent.change(screen.getByLabelText('Filter value'), { target: { value: 'ad' } })
    fireEvent.click(screen.getByRole('button', { name: 'Filter' }))
    expect(onChange).toHaveBeenCalledWith([{ col: 'name', op: 'contains', value: 'ad' }])
    const f: Filter[] = [{ col: 'name', op: 'contains', value: 'ad' }, { col: 'id', op: 'null', value: '' }]
    rerender(<FilterBar cols={['id', 'name']} filters={f} onChange={onChange} />)
    expect(screen.getByText('name contains ad')).toBeTruthy()
    expect(screen.getByText('id is NULL')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter name contains ad' }))
    expect(onChange).toHaveBeenLastCalledWith([{ col: 'id', op: 'null', value: '' }])
  })

  it('needs no value to look for NULL, and a value for anything else', () => {
    const onChange = vi.fn()
    render(<FilterBar cols={['id']} filters={[]} onChange={onChange} />)
    expect((screen.getByRole('button', { name: 'Filter' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Filter comparison'), { target: { value: 'notnull' } })
    expect(screen.queryByLabelText('Filter value')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Filter' }))
    expect(onChange).toHaveBeenCalledWith([{ col: 'id', op: 'notnull', value: '' }])
  })
})

describe('EditGrid', () => {
  const cols = ['id', 'name', 'total']
  const rows = [[1, 'Ada', 10], [2, 'Bob', null]]
  const info: ColInfo[] = [
    { name: 'id', type: 'integer', key: true },
    { name: 'name', type: 'text', key: false },
    { name: 'total', type: 'numeric', key: false, locked: 'Generated from other columns: (price * 2)' },
  ]
  const grid = (onSave = vi.fn(async (_changes: unknown) => {}), onCancel = vi.fn()) => {
    render(<EditGrid cols={cols} rows={rows} info={info} onSave={onSave} onCancel={onCancel} />)
    return { onSave, onCancel }
  }
  const cellOf = (row: number, col: number) => screen.getAllByRole('row')[row + 1].querySelectorAll('td')[col + 1] as HTMLElement

  it('edits a cell, sets one to NULL, deletes a row and adds one, then saves them together', async () => {
    const { onSave } = grid()
    fireEvent.click(cellOf(0, 1))
    const input = screen.getByLabelText('Value for name')
    fireEvent.change(input, { target: { value: 'Ada L.' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(cellOf(0, 1).className).toContain('cell-dirty')
    fireEvent.click(cellOf(1, 1))
    fireEvent.mouseDown(screen.getByRole('button', { name: 'NULL' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete row 2' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add row' }))
    const newRow = screen.getAllByRole('row')[3]
    expect(newRow.textContent).toContain('DEFAULT')
    fireEvent.click(newRow.querySelectorAll('td')[2])
    fireEvent.change(screen.getByLabelText('Value for name'), { target: { value: 'Cy' } })
    fireEvent.keyDown(screen.getByLabelText('Value for name'), { key: 'Enter' })
    expect(screen.getByRole('status').textContent).toMatch(/1 added, 1 changed, 1 deleted/)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(onSave.mock.calls[0][0]).toEqual([
      { op: 'delete', key: { id: '2' } },
      { op: 'update', key: { id: '1' }, values: { name: 'Ada L.' }, old: { name: 'Ada' } },
      { op: 'insert', values: { name: 'Cy' } },
    ])
  })

  it('will not edit a column Postgres fills itself, and says why', () => {
    grid()
    const c = cellOf(0, 2)
    expect(c.getAttribute('title')).toMatch(/generated/i)
    fireEvent.click(c)
    expect(screen.queryByLabelText('Value for total')).toBeNull()
  })

  it('Escape leaves a cell as it was; a deleted row can be kept again', () => {
    grid()
    fireEvent.click(cellOf(0, 1))
    fireEvent.change(screen.getByLabelText('Value for name'), { target: { value: 'nope' } })
    fireEvent.keyDown(screen.getByLabelText('Value for name'), { key: 'Escape' })
    expect(cellOf(0, 1).textContent).toBe('Ada')
    fireEvent.click(screen.getByRole('button', { name: 'Delete row 1' }))
    expect(screen.getAllByRole('row')[1].className).toBe('row-deleted')
    fireEvent.click(screen.getByRole('button', { name: 'Keep row 1' }))
    expect(screen.getByRole('status').textContent).toMatch(/click a cell/i)
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('keeps the edits and says nothing was saved when the save is refused', async () => {
    const onSave = vi.fn(async () => { throw new Error('change 1 (update): the row was changed or deleted since it was loaded') })
    grid(onSave)
    fireEvent.click(screen.getByRole('button', { name: 'Delete row 1' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/changed or deleted.*Nothing was saved/)
    expect(screen.getAllByRole('row')[1].className).toBe('row-deleted')
  })

  it('Discard leaves without saving', () => {
    const { onSave, onCancel } = grid()
    fireEvent.click(screen.getByRole('button', { name: 'Delete row 1' }))
    fireEvent.click(within(screen.getByRole('status').parentElement!).getByRole('button', { name: 'Discard' }))
    expect(onCancel).toHaveBeenCalled()
    expect(onSave).not.toHaveBeenCalled()
  })
})
