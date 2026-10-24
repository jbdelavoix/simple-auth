import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/oauth': 'http://127.0.0.1:8000',
      '/jwks.json': 'http://127.0.0.1:8000',
      '/.well-known': 'http://127.0.0.1:8000',
    },
  },
})
