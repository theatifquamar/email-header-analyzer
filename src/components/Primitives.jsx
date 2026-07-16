import React, { useState } from "react";
import { T, polColor, polSym } from "../theme.js";

export const Badge = ({ color, children }) => (
  <span
    style={{
      display: "inline-block",
      padding: "3px 10px",
      borderRadius: 999,
      fontSize: 11.5,
      fontFamily: T.mono,
      fontWeight: 700,
      letterSpacing: 0.4,
      color: "#0A0E1A",
      background: color,
      boxShadow: `0 1px 4px ${color}55`,
    }}
  >
    {children}
  </span>
);

export const Tag = ({ color, children }) => (
  <span
    style={{
      display: "inline-block",
      padding: "2px 9px",
      borderRadius: 5,
      fontSize: 11,
      fontFamily: T.mono,
      color,
      border: `1px solid ${color}4D`,
      background: color + "16",
      fontWeight: 500,
    }}
  >
    {children}
  </span>
);

/**
 * Collapsible — children are ALWAYS rendered to the DOM; visibility toggles
 * via a CSS class. This is deliberate: the print stylesheet forces every
 * `.collapsible-body` to display, so an "Analyze → export PDF" round trip
 * reproduces everything on screen even if a section was left closed.
 */
export function Collapsible({ title, right, children, open: initOpen = false, id }) {
  const [open, setOpen] = useState(initOpen);
  return (
    <div
      className="hf-card"
      data-collapsible
      style={{
        border: `1px solid ${T.line}`,
        borderRadius: T.r2,
        background: T.panel,
        marginBottom: 14,
        overflow: "hidden",
        boxShadow: T.shadowSm,
      }}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="no-print-toggle"
        aria-expanded={open}
        style={{
          width: "100%",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 10,
          background: "none",
          border: "none",
          color: T.ink,
          padding: "14px 18px",
          cursor: "pointer",
          fontFamily: T.disp,
          fontSize: 14.5,
          fontWeight: 600,
          textAlign: "left",
          transition: `background .15s ${T.ease}`,
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span
            style={{
              color: T.accent,
              fontFamily: T.mono,
              fontSize: 12,
              transform: open ? "rotate(90deg)" : "none",
              transition: `transform .2s ${T.ease}`,
              display: "inline-block",
            }}
          >
            ▶
          </span>
          {title}
        </span>
        <span>{right}</span>
      </button>
      <div
        className="collapsible-body"
        style={{
          display: open ? "block" : "none",
          padding: "2px 18px 18px",
        }}
      >
        {children}
      </div>
    </div>
  );
}

export function EvidenceRow({ e }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 12,
        padding: "11px 0",
        borderBottom: `1px solid ${T.line}66`,
      }}
    >
      <div style={{ color: polColor(e.pol), fontFamily: T.mono, fontWeight: 700, width: 18, flexShrink: 0 }}>
        {polSym(e.pol)}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 13.5, color: T.ink }}>
          {e.label}
          {e.w !== 0 && (
            <span style={{ marginLeft: 8, fontFamily: T.mono, fontSize: 11, color: polColor(e.pol) }}>
              {e.pol === "neg" ? "−" : e.w > 0 ? "+" : ""}
              {Math.abs(e.w)}
            </span>
          )}
        </div>
        <div style={{ fontSize: 12.5, color: T.dim, marginTop: 3, lineHeight: 1.55 }}>{e.detail}</div>
      </div>
    </div>
  );
}
