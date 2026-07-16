import React from "react";
import { T } from "../theme.js";

export function CreditsBanner() {
  return (
    <div
      className="no-print"
      style={{
        background: "linear-gradient(90deg, rgba(245,184,65,0.10), rgba(255,138,76,0.06) 40%, transparent 80%)",
        borderBottom: `1px solid ${T.line}`,
        padding: "9px 22px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
        flexWrap: "wrap",
        fontSize: 13,
        fontFamily: T.body,
      }}
    >
      <span style={{ fontSize: 14 }}>✨</span>
      <span style={{ color: T.dim }}>
        Created with love by{" "}
        <a
          href="https://www.linkedin.com/in/theatifquamar/"
          target="_blank"
          rel="noreferrer"
          style={{ color: T.accent, fontWeight: 700, textDecoration: "none", borderBottom: `1px solid ${T.accent}66` }}
        >
          Atif Quamar
        </a>
        , for the cybersecurity community.
      </span>
      <span aria-hidden="true">❤️</span>
    </div>
  );
}
