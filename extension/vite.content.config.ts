import { defineConfig } from 'vite';
import { resolve } from 'path';

/**
 * Builds content/contentScript.ts as a single self-contained IIFE bundle.
 * Chrome content scripts MUST NOT contain ES module 'import' statements.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@shared': resolve(__dirname, './shared'),
      '@background': resolve(__dirname, './background'),
      '@popup': resolve(__dirname, './popup'),
      '@content': resolve(__dirname, './content'),
      '@options': resolve(__dirname, './options'),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, 'content/contentScript.ts'),
      name: 'SafeClickContent',
      formats: ['iife'],
      fileName: () => 'content/contentScript.js',
    },
    rollupOptions: {
      output: {
        extend: true,
      },
    },
  },
});
