// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest'
import { splitFrames } from './sse'

it('returns whole frames and carries the rest forward', () => {
  const { frames, rest } = splitFrames('event: message\ndata: {"a":1}\n\nevent: message\ndata: {"b"')
  expect(frames).toEqual([{ event: 'message', data: '{"a":1}' }])
  expect(rest).toBe('event: message\ndata: {"b"')
})

// A chunked response splits wherever the network felt like it, including in the
// middle of a frame and in the middle of the blank line that ends one.
it('reassembles a frame split across reads', () => {
  let buf = ''
  const got: string[] = []
  for (const chunk of ['event: mes', 'sage\ndata: {"id"', ':"7"}\n', '\nevent: message\ndata: {}\n\n']) {
    buf += chunk
    const { frames, rest } = splitFrames(buf)
    buf = rest
    for (const f of frames) got.push(f.data)
  }
  expect(got).toEqual(['{"id":"7"}', '{}'])
  expect(buf).toBe('')
})

// Comment lines keep a connection warm and carry nothing.
it('ignores keep-alive comments', () => {
  const { frames } = splitFrames(': keep-alive\n\ndata: {"a":1}\n\n')
  expect(frames).toEqual([{ event: 'message', data: '' }, { event: 'message', data: '{"a":1}' }])
})

it('joins multiple data lines in one frame', () => {
  const { frames } = splitFrames('data: {"a":\ndata: 1}\n\n')
  expect(frames[0].data).toBe('{"a":1}')
})

it('defaults the event name to message', () => {
  const { frames } = splitFrames('data: {}\n\n')
  expect(frames[0].event).toBe('message')
})
