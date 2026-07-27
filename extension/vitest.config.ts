import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./vitest.setup.ts'],
    include: ['**/*.test.ts', '**/*.test.tsx'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['shared/**/*.ts', 'background/**/*.ts'],
    },
  },
  resolve: {
    alias: {
      '@shared': resolve(__dirname, './shared'),
      '@background': resolve(__dirname, './background'),
    },
  },
});
