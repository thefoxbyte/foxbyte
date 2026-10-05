/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Component tests run here rather than in a second config: one place to look,
  // and the tests compile through the same pipeline the app does. The triple-slash
  // reference above is what teaches vite's defineConfig about `test`; importing
  // defineConfig from vitest/config instead would make the production build
  // depend on the test runner.
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
