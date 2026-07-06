import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Relative base so the built site works from any path
  // (GitHub Pages subpaths, S3 prefixes, nginx subdirectories, etc.)
  base: "./",
  build: {
    sourcemap: false,
    target: "es2020",
  },
});
