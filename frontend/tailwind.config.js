/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0B1220",       // base background (blue-black SOC)
        panel: "#141E33",     // surface
        panel2: "#1B2740",    // raised surface
        line: "#263350",      // borders
        mist: "#8A97B1",      // secondary text
        paper: "#E8ECF5",     // primary text
        signal: "#E8B23A",    // brand accent — "the watch" (use with restraint)
        crit: "#F0546D",      // risk: critical
        high: "#F2913D",      // risk: high
        med: "#E7C548",       // risk: medium
        low: "#4CC9A0",       // risk: low / ok
        info: "#5AA6FF",      // reachable / graph edges
      },
      fontFamily: {
        display: ['"Space Grotesk"', "system-ui", "sans-serif"],
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 1px rgba(232,178,58,0.35), 0 0 24px -6px rgba(232,178,58,0.35)",
      },
    },
  },
  plugins: [],
};
