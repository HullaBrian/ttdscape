import { defineConfig } from 'vite';

export default defineConfig({
  root: 'client',
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 1500 },
  server: {
    // `npm run dev` proxies the API to a running `npm start`.
    proxy: { '/api': { target: 'http://127.0.0.1:5177', changeOrigin: true } },
  },
});
