import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  output: 'server',
  adapter: node({
    mode: 'standalone',
    bodySizeLimit: 128 * 1024
  }),
  security: {
    checkOrigin: true,
    allowedDomains: [
      { protocol: 'https', hostname: 'evolutioncloud.net' },
      { protocol: 'https', hostname: 'www.evolutioncloud.net' },
      { protocol: 'https', hostname: 'test.evolutioncloud.net' }
    ]
  },
  vite: {
    resolve: {
      preserveSymlinks: true
    },
    plugins: [tailwindcss()]
  }
});
