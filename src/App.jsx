import React, { useState } from "react";
import { T } from "./theme.js";
import { NavBar } from "./components/NavBar.jsx";
import { CreditsBanner } from "./components/CreditsBanner.jsx";
import { AnalyzerPage } from "./pages/Analyzer.jsx";
import { HowItWorksPage } from "./pages/HowItWorks.jsx";
import { GlossaryPage } from "./pages/Glossary.jsx";
import { PolicyPage } from "./pages/Policy.jsx";

/* ============================================================
   HEADER FORENSICS — privacy-first email header analysis for SOC analysts
   All processing happens in browser memory. No storage APIs are used,
   nothing is logged, persisted, or transmitted except optional
   DNS-over-HTTPS lookups (hostnames/IPs only) that the analyst enables.
   Created by Atif Quamar — https://www.linkedin.com/in/theatifquamar/
   ============================================================ */

export default function App() {
  const [page, setPage] = useState("analyzer");

  return (
    <div style={{ minHeight: "100vh", background: T.bgGrad, color: T.ink, fontFamily: T.body }}>
      <style>{`
        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body { margin: 0; }
        textarea:focus, button:focus-visible, a:focus-visible, input:focus-visible {
          outline: 2px solid ${T.accent}; outline-offset: 2px;
        }
        a { color: ${T.info}; text-decoration: none; }
        ::selection { background: ${T.accent}44; }
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: ${T.bg}; }
        ::-webkit-scrollbar-thumb { background: ${T.line}; border-radius: 99px; }
        ::-webkit-scrollbar-thumb:hover { background: ${T.faint}; }
        .hf-card { transition: box-shadow .2s ${T.ease}, border-color .2s ${T.ease}; }
        button { font-family: inherit; }
        code { background: ${T.panel2}; padding: 1px 6px; border-radius: 4px; font-size: 0.92em; }
        @media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }

        /* ---------------------------------------------------------
           PRINT / PDF EXPORT
           Root cause of PDF mismatch: browsers strip background
           colors by default unless explicitly told to keep them.
           print-color-adjust: exact restores the on-screen palette,
           gradients, and shadows verbatim in the printed/PDF output.
           --------------------------------------------------------- */
        @media print {
          html, body { background: ${T.bg} !important; }
          * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
            color-adjust: exact !important;
          }
          .no-print { display: none !important; }
          .print-header { display: flex !important; flex-direction: column; }
          /* Collapsibles always render their body in the DOM (see
             Collapsible.jsx) — this forces every section open for print
             regardless of what the analyst left expanded on screen. */
          .collapsible-body { display: block !important; }
          .no-print-toggle { pointer-events: none; }
          main { grid-template-columns: 1fr !important; }
          .hf-card, [data-collapsible] { break-inside: avoid; box-shadow: none !important; }
          @page { margin: 14mm; }
        }
      `}</style>

      <NavBar page={page} setPage={setPage} />
      <CreditsBanner />

      {page === "analyzer" && <AnalyzerPage />}
      {page === "how" && <HowItWorksPage />}
      {page === "glossary" && <GlossaryPage />}
      {page === "policy" && <PolicyPage />}

      <footer
        className="no-print"
        style={{
          borderTop: `1px solid ${T.line}`,
          padding: "18px 22px",
          fontSize: 11.5,
          fontFamily: T.mono,
          color: T.faint,
          lineHeight: 1.7,
          maxWidth: 1280,
          margin: "0 auto",
        }}
      >
        PRIVACY: analysis runs entirely in this tab's memory. No storage APIs are used; nothing is logged,
        persisted, indexed, trained on, or shared. Optional DNS-over-HTTPS enrichment transmits only IP
        addresses and domain names to the public resolver you can disable above. Closing or reloading the
        page destroys all data, including the in-memory DNS cache.
        <div style={{ marginTop: 8, color: T.faint }}>
          Header Forensics · Created by{" "}
          <a href="https://www.linkedin.com/in/theatifquamar/" target="_blank" rel="noreferrer" style={{ color: T.faint, textDecoration: "underline" }}>
            Atif Quamar
          </a>{" "}
          · See the <button onClick={() => setPage("policy")} style={{ background: "none", border: "none", color: T.faint, textDecoration: "underline", cursor: "pointer", padding: 0, fontFamily: T.mono, fontSize: 11.5 }}>Policy</button> page for terms, warranty, and liability information.
        </div>
      </footer>
    </div>
  );
}
