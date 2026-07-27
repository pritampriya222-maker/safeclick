/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './popup/**/*.{ts,tsx,html}',
    './options/**/*.{ts,tsx,html}',
    './shared/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      colors: {
        // SafeClick brand palette
        brand: {
          indigo: '#6366f1',
          purple: '#a855f7',
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
