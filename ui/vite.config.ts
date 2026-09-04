import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * Ward's SPA, served at `/ward` on the estate's single origin.
 *
 * `base` is not cosmetic. Caddy serves this build under `/ward/*`, so every
 * asset URL Vite emits has to carry that prefix or the page loads and its
 * JavaScript 404s — the failure that looks like "the login page is blank".
 * Atrium learned the same lesson the other way round: it baked an absolute
 * origin into its bundle, which is one of the reasons the estate is stuck on
 * sub-paths (see wiki/decisions.md). A relative base keeps this build portable
 * if that ever changes.
 */
export default defineConfig({
  plugins: [react()],
  base: "/ward/",
  server: {
    /**
     * `/ward-api` is proxied in development so the browser sees one origin,
     * exactly as it will in production behind Caddy. Without this the cookies
     * would be cross-site in dev and same-site in prod — and `SameSite=Lax`
     * behaves differently across that line, so the bug would only ever appear
     * in the environment you cannot debug.
     */
    proxy: {
      "/ward-api": {
        target: "http://127.0.0.1:8791",
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/ward-api/, ""),
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
