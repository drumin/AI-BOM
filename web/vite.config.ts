import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  root: path.resolve(import.meta.dirname),
  plugins: [react()],
  build: {
    outDir: path.resolve(import.meta.dirname, '..', 'dist', 'web'),
    emptyOutDir: true,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    // `npm run dev:web` while `npm run ui -- --no-open` serves the API.
    proxy: { '/api': 'http://127.0.0.1:7654' },
  },
});
