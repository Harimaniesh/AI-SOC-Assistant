/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#090d16",       // Deep dark space background
          card: "#0f172a",     // Dark slate card background
          accent: "#14b8a6",   // Neon teal
          glow: "#3b82f6",     // Neon blue glow
          success: "#10b981",  // Neon green
          warning: "#f59e0b",  // Alert yellow/orange
          danger: "#ef4444",   // Critical red
          border: "#1e293b",   // Subtle borders
          text: "#94a3b8"      // Muted gray text
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-teal': '0 0 15px rgba(20, 184, 166, 0.15)',
        'glow-blue': '0 0 15px rgba(59, 130, 246, 0.15)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.2)',
      }
    },
  },
  plugins: [],
}
