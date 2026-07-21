import React from "react";
import { T } from "../theme.js";

const PAGES = [
  { id: "analyzer", label: "Analyzer" },
  { id: "how", label: "How It Works" },
  { id: "glossary", label: "Glossary" },
  { id: "policy", label: "Policy" },
];

export function NavBar({ page, setPage }) {
  return (
    <header
      className="no-print"
      style={{
        borderBottom: `1px solid ${T.line}`,
        padding: "14px 22px",
        display: "flex",
        alignItems: "center",
        gap: 22,
        flexWrap: "wrap",
        position: "sticky",
        top: 0,
        zIndex: 20,
        background: "rgba(10,14,26,0.92)",
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
      }}
    >
      <div
        onClick={() => setPage("analyzer")}
        style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}
      >
        <img
          src="/favicon.svg"
          alt="Email Header Forensics logo"
          width={34}
          height={37}
          style={{ display: "block", filter: `drop-shadow(0 0 10px ${T.accent}33)` }}
        />
        <div style={{ fontFamily: T.disp, fontWeight: 700, fontSize: 16.5, letterSpacing: 0.2, color: T.ink }}>
          EMAIL HEADER FORENSICS
        </div>
      </div>

      <nav style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
        {PAGES.map((p) => {
          const active = page === p.id;
          return (
            <button
              key={p.id}
              onClick={() => setPage(p.id)}
              style={{
                background: active ? T.panel2 : "transparent",
                color: active ? T.ink : T.dim,
                border: `1px solid ${active ? T.line : "transparent"}`,
                borderRadius: 8,
                padding: "7px 14px",
                fontSize: 13,
                fontFamily: T.disp,
                fontWeight: active ? 700 : 500,
                cursor: "pointer",
                transition: `all .15s ${T.ease}`,
              }}
            >
              {p.label}
            </button>
          );
        })}
      </nav>

      <div
        style={{
          marginLeft: "auto",
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontFamily: T.mono,
          fontSize: 11,
          color: T.good,
          background: T.goodSoft,
          border: `1px solid ${T.good}33`,
          borderRadius: 999,
          padding: "5px 12px",
        }}
      >
        <span style={{ width: 7, height: 7, borderRadius: 99, background: T.good, display: "inline-block", boxShadow: `0 0 6px ${T.good}` }} />
        IN-MEMORY ONLY
      </div>
    </header>
  );
}
