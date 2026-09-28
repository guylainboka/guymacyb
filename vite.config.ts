import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    // Restreint le scan de dépendances aux vrais points d'entrée de l'app.
    // Sans ceci, Vite scannait tout le dossier skills/ (templates HTML tiers
    // important three.js…) et échouait à pré-bundler.
    optimizeDeps: {
      entries: ['index.html', 'src/main.tsx'],
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {
        // Le dossier skills/ contient des centaines de templates tiers sans
        // rapport avec l'app — les ignorer évite toute recompilation parasite.
        ignored: ['**/skills/**', '**/node_modules/**', '**/.git/**'],
      },
    },
    // `vite preview` sert le build statique seul ; sans proxy, chaque appel
    // /api/* renvoyait 404. On relaie vers le backend Express (tsx server.ts).
    preview: {
      proxy: {
        '/api': {
          target: process.env.GCYB_API_TARGET || 'http://127.0.0.1:3000',
          changeOrigin: true,
        },
      },
    },
  };
});
