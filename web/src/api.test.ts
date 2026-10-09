// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What req() does with a body that is not JSON.
//
// This is the bug that crashed the Realtime page on a Standard build. The paid
// routes are not compiled into that binary, so the request fell through to the
// console's own catch-all and came back as index.html with status 200. req()
// did `r.json().catch(() => ({}))`, so every caller received an empty object
// that was indistinguishable from a real response with missing fields — and
// the page died on `rows.length`, reading undefined where an array was
// promised, with an error that named a property instead of the missing route.
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { ApiError, getStatus } from './api'

const realFetch = globalThis.fetch

function reply(body: string, init: { status?: number; ok?: boolean } = {}) {
  const status = init.status ?? 200
  globalThis.fetch = vi.fn(async () => ({
    ok: init.ok ?? (status >= 200 && status < 300),
    status,
    text: async () => body,
  })) as unknown as typeof fetch
}

beforeEach(() => { vi.restoreAllMocks() })
afterEach(() => { globalThis.fetch = realFetch })

it('rejects a 200 that is not JSON, naming the likely cause', async () => {
  reply('<!doctype html>\n<html lang="en"><head><title>FoxByte</title></head></html>')
  await expect(getStatus()).rejects.toThrow(ApiError)
  // The message has to point at the route, not at a property: "undefined is
  // not an object" sent me looking at the page for an hour.
  await expect(getStatus()).rejects.toThrow(/did not return JSON/)
  await expect(getStatus()).rejects.toThrow(/route may not exist/)
})

it('still accepts an empty body as an empty object', async () => {
  // A handler that writes nothing is not an error — DELETE answers this way.
  reply('')
  await expect(getStatus()).resolves.toEqual({})
})

it('parses an ordinary JSON response', async () => {
  reply(JSON.stringify({ edition: 'standard', features: [] }))
  await expect(getStatus()).resolves.toEqual({ edition: 'standard', features: [] })
})

it('still reports the error field of a failed response', async () => {
  reply(JSON.stringify({ error: 'no branch "nope"' }), { status: 404 })
  await expect(getStatus()).rejects.toThrow(/no branch/)
})

it('a non-JSON error body still throws with its status', async () => {
  // A proxy's own error page, say. The status is what the caller can act on.
  reply('<html>502 Bad Gateway</html>', { status: 502 })
  await expect(getStatus()).rejects.toThrow(/502/)
})
