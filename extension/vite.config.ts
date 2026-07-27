import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

/**
 * vite.config.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Multi-entry Vite build for the SafeClick Chrome extension.
 *
 * Entries:
 *   popup      → popup/popup.html   (React UI)
 *   options    → options/options.html (React settings page)
 *   background → background/service-worker.ts (MV3 service worker, ES module)
 *   content    → content/contentScript.ts (injected into pages, IIFE format)
 *
 * Output: extension/dist/ — loadable as unpacked extension in Chrome.
 *
 * Design decisions:
 * - Background service worker must be a single flat JS file (Chrome MV3 requirement).
 *   We achieve this with rollup's output.entryFileNames pointing to service-worker.js.
 * - Content script is built as IIFE (not ESM) because Chrome injects content scripts
 *   as classic scripts into page contexts, not as modules.
 * - Popup and options use standard HTML entry points so Vite handles asset hashing.
 * - manifest.json and icons/ are copied to dist/ via a custom plugin since Vite
 *   does not automatically copy the extension manifest or icon assets.
 */

/**
 * Custom plugin to copy extension-specific static files (manifest.json, icons/)
 * to the dist/ output directory after each build.
 */
function copyExtensionFiles(): Plugin {
  return {
    name: 'copy-extension-files',
    closeBundle() {
      const root = resolve(__dirname);
      const dist = resolve(__dirname, 'dist');

      // Copy manifest.json
      copyFileSync(join(root, 'manifest.json'), join(dist, 'manifest.json'));
      console.log('[SafeClick] Copied manifest.json → dist/');

      // Copy icons/
      const iconsDir = join(root, 'icons');
      const distIconsDir = join(dist, 'icons');
      mkdirSync(distIconsDir, { recursive: true });
      readdirSync(iconsDir).forEach((file) => {
        const src = join(iconsDir, file);
        const dest = join(distIconsDir, file);
        if (statSync(src).isFile()) {
          copyFileSync(src, dest);
        }
      });
      console.log('[SafeClick] Copied icons/ → dist/icons/');
    },
  };
}

export default defineConfig({
  plugins: [react(), copyExtensionFiles()],
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
    emptyOutDir: true,
    sourcemap: process.env.NODE_ENV === 'development',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup/popup.html'),
        options: resolve(__dirname, 'options/options.html'),
        background: resolve(__dirname, 'background/service-worker.ts'),
        content: resolve(__dirname, 'content/contentScript.ts'),
      },
      output: {
        // Place background service worker at a predictable path matching manifest.json
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') return 'background/service-worker.js';
          if (chunk.name === 'content') return 'content/contentScript.js';
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
        format: 'es',
      },
    },
  },
  // During 'vite build --watch' (dev mode), skip minification for readability.
  esbuild: {
    minify: false,
  },
});
