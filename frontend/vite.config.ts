import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import basicSsl from '@vitejs/plugin-basic-ssl';
import federation from '@originjs/vite-plugin-federation';

// https://vitejs.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [
    react(),
    basicSsl(),
    federation({
      name: 'host',
      filename: 'remoteEntry.js',
      exposes: {
        './pluginCardRegistry': './src/features/plugins/store/pluginCardRegistry',
      },
      // CRITICAL: NO shared array — adding shared externalizes react/zustand and breaks the app
    }),
  ],
  base: command === 'serve' ? '/' : '/staticfiles/',
  build: {
    manifest: true,
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // Main entry points should NOT have hashes for Django compatibility
        entryFileNames: 'assets/[name].js',
        // Chunks carry a content hash: a tab still running the previous build must
        // never load a chunk of the new one under the same name (their minified
        // export names differ). Only the entry keeps a stable name, for the
        // Django template; it imports the hashed chunks itself.
        chunkFileNames: 'assets/[name]-[hash].js',
        // Assets like CSS should also have stable names if possible
        assetFileNames: 'assets/[name].[ext]',
        manualChunks: (id) => {
          if (!id.includes('node_modules')) return;

          // Normalize Windows paths for reliable matching
          const p = id.replace(/\\/g, '/');

          // Core React runtime (kept tight — only the runtime itself)
          if (p.includes('/react/') || p.includes('/react-dom/') || p.includes('/scheduler/')) {
            return 'vendor-react';
          }

          // TanStack router + query + react-router
          if (p.includes('@tanstack') || p.includes('react-router')) {
            return 'vendor-router';
          }

          // MUI core + icons + Emotion
          if (p.includes('@mui/') || p.includes('@emotion/')) {
            return 'vendor-mui';
          }

          // Small icon set
          if (p.includes('lucide-react')) {
            return 'vendor-icons';
          }

          // ECharts + react wrapper + rendering engine
          if (p.includes('echarts') || p.includes('zrender')) {
            return 'vendor-echarts';
          }

          // ApexCharts
          if (p.includes('apexcharts') || p.includes('react-apexcharts')) {
            return 'vendor-viz';
          }

          // Cytoscape graph engine + plugins + react binding
          if (p.includes('cytoscape') || p.includes('react-cytoscapejs')) {
            return 'vendor-cytoscape';
          }

          // D3 ecosystem
          if (p.includes('/d3-') || p.includes('/d3/')) {
            return 'vendor-d3';
          }

          // Geo / map rendering
          if (p.includes('leaflet') || p.includes('react-leaflet')) {
            return 'vendor-geo';
          }

          // Syntax highlighting
          if (
            p.includes('prismjs') ||
            p.includes('prism-react-renderer') ||
            p.includes('react-simple-code-editor') ||
            p.includes('highlight.js')
          ) {
            return 'vendor-code';
          }

          // Drag-and-drop
          if (p.includes('@dnd-kit')) {
            return 'vendor-dnd';
          }

          // Mermaid docs/diagram stack (largest former vendor-base occupant)
          if (
            p.includes('mermaid') ||
            p.includes('/katex/') ||
            p.includes('katex') ||
            p.includes('/dagre/') ||
            p.includes('dagre-d3') ||
            p.includes('langium') ||
            p.includes('vscode-languageserver') ||
            p.includes('vscode-uri') ||
            p.includes('chevrotain') ||
            p.includes('roughjs') ||
            p.includes('/khroma/') ||
            p.includes('cose-base') ||
            p.includes('layout-base') ||
            p.includes('avsdf-base') ||
            p.includes('@braintree/sanitize-url')
          ) {
            return 'vendor-mermaid';
          }

          // Self-hosted font CSS packages
          if (p.includes('@fontsource/')) {
            return 'vendor-fonts';
          }

          // General utilities + markdown pipeline
          if (
            p.includes('axios') ||
            p.includes('date-fns') ||
            p.includes('lodash') ||
            p.includes('react-markdown') ||
            p.includes('dompurify') ||
            p.includes('zustand') ||
            p.includes('js-yaml') ||
            p.includes('remark-') ||
            p.includes('micromark') ||
            p.includes('mdast-') ||
            p.includes('unist-') ||
            p.includes('hast-') ||
            p.includes('/unified/') ||
            p.includes('clsx') ||
            p.includes('property-information') ||
            p.includes('vfile') ||
            p.includes('decode-named-character-reference') ||
            p.includes('character-entities') ||
            p.includes('ccount') ||
            p.includes('escape-string-regexp') ||
            p.includes('markdown-table') ||
            p.includes('trim-lines') ||
            p.includes('style-to-object') ||
            p.includes('inline-style-parser') ||
            p.includes('extend') ||
            p.includes('devlop') ||
            p.includes('comma-separated-tokens') ||
            p.includes('space-separated-tokens') ||
            p.includes('html-url-attributes') ||
            p.includes('estree-util') ||
            p.includes('@types/estree') ||
            p.includes('parse-entities') ||
            p.includes('is-plain-obj')
          ) {
            return 'vendor-utils';
          }

          return 'vendor-base';
        },
      },
    },
  },
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
        secure: false,
      },
      '/login': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/logout': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/onboarding': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/static': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
      '/media': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      }
    }
  }
}));
