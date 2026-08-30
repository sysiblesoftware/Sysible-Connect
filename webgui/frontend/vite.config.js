import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: proxy the API + terminal websocket to the backend on :8700 so `npm run dev`
// (Vite on :5173) talks to it. Prod: the backend serves the built dist/ itself.
//
// SYSIBLE_BASE_PATH is the URL prefix the console is served under: "/" standalone,
// "/connect/" behind the SLOP gateway (which path-routes /connect/* to this app on
// one shared origin). Vite prefixes every asset URL; the SPA reads it back via
// import.meta.env.BASE_URL to prefix its API calls + terminal websocket (src/api.js).
export default defineConfig({
  base: process.env.SYSIBLE_BASE_PATH || '/',
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8700', changeOrigin: true, ws: true },
      '/healthz': 'http://localhost:8700',
    },
  },
})
