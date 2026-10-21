import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // Never inline a font as a data: URI. Vite inlines any asset under 4 KB by
    // default, which caught the smallest subsets of the bundled fonts, and the
    // console's Content-Security-Policy allows fonts from this server only
    // (font-src 'self'), so an inlined one was blocked. Every other asset keeps
    // the default.
    assetsInlineLimit: (file) => (/\.woff2?$/.test(file) ? false : undefined),
  },
  // Component tests run here rather than in a second config: one place to look,
  // and the tests compile through the same pipeline the app does.
  //
  // This used to import defineConfig from 'vite' and teach it about `test` with
  // `/// <reference types="vitest" />`, so that the build did not reach for the
  // test runner at all. Vitest 3 removed that augmentation, and on vitest 5 the
  // reference compiles to `'test' does not exist in type 'UserConfigExport'`.
  // Importing from vitest/config is the supported path now, and it costs
  // nothing real: this file is only ever read by the tooling, which already has
  // vitest as a devDependency, and none of it reaches the shipped bundle.
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
