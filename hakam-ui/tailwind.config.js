/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#0b0e14',
          900: '#0a101f',
        },
        cyan: {
          400: '#00f0ff', /* Electric Blue */
          500: '#00d0e0',
        },
        amber: {
          500: '#ff9100', /* Radiant Orange */
        },
        crimson: {
          500: '#ff003c', /* Deep Crimson Red */
          600: '#cc0030',
        },
        phantomCyan: '#00f0ff',
        phantomAmber: '#ff9100',
        phantomRed: '#ff003c'
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
