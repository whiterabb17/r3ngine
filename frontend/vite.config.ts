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
        // Chunks should NOT have hashes for stable template integration
        chunkFileNames: 'assets/[name].js',
        // Assets like CSS should also have stable names if possible
        assetFileNames: 'assets/[name].[ext]',
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            // Core React runtime (kept tight — only the runtime itself)
            if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) return 'vendor-react';

            // TanStack router + query
            if (id.includes('@tanstack')) return 'vendor-router';

            // MUI core + icons + Emotion (icons tree-shaken to only used set via main.tsx registry)
            if (id.includes('@mui/') || id.includes('@emotion/')) return 'vendor-mui';

            // Small icon set
            if (id.includes('lucide-react')) return 'vendor-icons';

            // ECharts + its rendering engine
            if (id.includes('echarts') || id.includes('zrender')) return 'vendor-echarts';

            // ApexCharts
            if (id.includes('apexcharts') || id.includes('react-apexcharts')) return 'vendor-viz';

            // Cytoscape graph engine + all layout plugins
            if (id.includes('cytoscape')) return 'vendor-cytoscape';

            // D3 ecosystem
            if (id.includes('/d3-') || id.includes('/d3/') || id.includes('d3-scale')) return 'vendor-d3';

            // Geo / map rendering
            if (id.includes('leaflet') || id.includes('react-leaflet')) return 'vendor-geo';

            // Syntax highlighting
            if (id.includes('prismjs') || id.includes('prism-react-renderer') || id.includes('react-simple-code-editor')) return 'vendor-code';

            // Drag-and-drop
            if (id.includes('@dnd-kit')) return 'vendor-dnd';

            // General utilities
            if (id.includes('axios') || id.includes('date-fns') || id.includes('lodash') || id.includes('react-markdown') || id.includes('dompurify') || id.includes('zustand') || id.includes('js-yaml')) return 'vendor-utils';

            return 'vendor-base';
          }
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
