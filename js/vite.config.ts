import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import dts from 'vite-plugin-dts';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [
    react(),
    dts({ rollupTypes: true, tsconfigPath: './tsconfig.json' }),
  ],
  css: {
    modules: { localsConvention: 'camelCase' },
  },
  build: {
    lib: {
      entry: fileURLToPath(new URL('./src/index.ts', import.meta.url)),
      name: 'PatternAuthReact',
      formats: ['es', 'cjs'],
      fileName: (format) => (format === 'es' ? 'index.js' : 'index.cjs'),
    },
    rollupOptions: {
      external: ['react', 'react-dom', 'react/jsx-runtime'],
      output: {
        assetFileNames: (info) =>
          info.name?.endsWith('.css') ? 'styles.css' : 'assets/[name][extname]',
      },
    },
    cssCodeSplit: false,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
