// SPDX-License-Identifier: AGPL-3.0-or-later

// Splitting a text/event-stream into frames.
//
// Extracted so the change feed and the import stream agree on what a frame is,
// and so the agreement can be tested without a server. consumeSSE in api.ts
// still has its own copy of this loop and is deliberately left alone: it throws
// when a stream ends without a result, which is right for a migration that has
// to finish and wrong for a feed that runs until you close it. Changing it to
// suit the feed would have changed what an import does on a dropped connection.

export type Frame = { event: string; data: string }

// splitFrames takes whatever has arrived so far and returns the complete frames
// in it, plus the remainder to carry forward. A frame ends at a blank line.
export function splitFrames(buffer: string): { frames: Frame[]; rest: string } {
  const frames: Frame[] = []
  let rest = buffer
  for (;;) {
    const i = rest.indexOf('\n\n')
    if (i < 0) break
    const chunk = rest.slice(0, i)
    rest = rest.slice(i + 2)
    let event = 'message'
    let data = ''
    for (const line of chunk.split('\n')) {
      // A line starting with ':' is a comment, which is how a server keeps the
      // connection warm. It carries nothing and must not be parsed as data.
      if (line.startsWith(':')) continue
      if (line.startsWith('event:')) event = line.slice(6).trim()
      // Multiple data: lines in one frame are joined, per the spec.
      else if (line.startsWith('data:')) data += line.slice(5).trim()
    }
    frames.push({ event, data })
  }
  return { frames, rest }
}
