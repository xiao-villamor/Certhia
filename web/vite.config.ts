import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit({ adapter: adapter({ fallback: '200.html', precompress: true }) })],
  server: {
    proxy: {
      '/api': { target: process.env.CERTHIA_API_URL ?? 'http://127.0.0.1:8080', changeOrigin: false }
    }
  }
});
