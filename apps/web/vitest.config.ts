import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    name: "web",
    environment: "jsdom",
    globals: true,
    include: ["tests/**/*.test.{ts,tsx}"],
    // next-intl's ESM imports `next/server` without an extension; vite has to resolve it.
    server: { deps: { inline: ["next-intl"] } },
  },
});
