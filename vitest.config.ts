import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@openactionrecord\/core\/standalone$/, replacement: src('./packages/core/src/standalone.ts') },
      { find: /^@openactionrecord\/core\/testing$/, replacement: src('./packages/core/src/testing/index.ts') },
      { find: /^@openactionrecord\/core$/, replacement: src('./packages/core/src/index.ts') },
      { find: /^@openactionrecord\/mcp$/, replacement: src('./packages/mcp/src/index.ts') },
    ],
  },
  test: {
    include: ['packages/*/src/**/*.test.ts', 'scripts/**/*.test.ts'],
    testTimeout: 20_000,
  },
});
