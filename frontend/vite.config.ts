import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// base './' so the production build works when served from any path (static deploy).
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: { port: 5173 },
});
