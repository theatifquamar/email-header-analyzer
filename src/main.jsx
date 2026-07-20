import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";

// Self-hosted fonts (latin-only, woff2-only — see fonts.css for why).
// Bundled by Vite as same-origin static assets: no external font CDN,
// no CSP change needed, font-src 'self' already covers this.
import "./fonts.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
