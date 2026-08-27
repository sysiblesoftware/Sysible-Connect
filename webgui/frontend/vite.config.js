import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: proxy the API + terminal websocket to the backend on :8700 so `npm run dev`
// (Vite on :5173) talks to it. Prod: the backend serves the built dist/ itself.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8700', changeOrigin: true, ws: true },
      '/healthz': 'http://localhost:8700',
    },
  },
})
