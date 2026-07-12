/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Société Générale palette: pure black, one red, disciplined neutrals.
        ink: "#000000",       // page background — pure black
        panel: "#0C0C0E",     // surface
        panel2: "#151519",    // raised surface
        line: "#26262C",      // borders
        mist: "#8A8A93",      // secondary text
        paper: "#F4F4F5",     // primary text
        signal: "#E60028",    // Société Générale red — the single accent
        crit: "#E60028",      // risk: critical = SG red
        high: "#F2733B",      // risk: high (warm)
        med: "#D9A441",       // risk: medium (muted amber)
        low: "#45B08A",       // risk: low (muted green)
        slate: "#79808F",     // governance risks (license) — neutral, not chromatic
        info: "#8A8A93",      // neutral
      },
      fontFamily: {
        display: ['"Space Grotesk"', "system-ui", "sans-serif"],
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.7)",
        glow: "0 0 0 1px rgba(230,0,40,0.35), 0 0 24px -6px rgba(230,0,40,0.35)",
      },
    },
  },
  plugins: [],
};
