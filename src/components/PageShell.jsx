import React from "react";
import { T } from "../theme.js";

export function PageShell({ eyebrow, title, subtitle, children, wide }) {
  return (
    <div style={{ maxWidth: wide ? 1100 : 860, margin: "0 auto", padding: "40px 22px 70px" }}>
      <div style={{ marginBottom: 34 }}>
        {eyebrow && (
          <div style={{ fontFamily: T.mono, fontSize: 12, color: T.accent, letterSpacing: 1.2, marginBottom: 8, fontWeight: 700 }}>
            {eyebrow}
          </div>
        )}
        <h1 style={{ fontFamily: T.disp, fontSize: 34, fontWeight: 700, color: T.ink, margin: 0, letterSpacing: -0.3 }}>
          {title}
        </h1>
        {subtitle && (
          <p style={{ fontSize: 15.5, color: T.dim, marginTop: 12, lineHeight: 1.65, maxWidth: 720 }}>{subtitle}</p>
        )}
      </div>
      {children}
    </div>
  );
}

export function Section({ title, icon, children, id }) {
  return (
    <section
      id={id}
      style={{
        background: T.panel,
        border: `1px solid ${T.line}`,
        borderRadius: T.r3,
        padding: "26px 28px",
        marginBottom: 20,
        boxShadow: T.shadowSm,
      }}
    >
      {title && (
        <h2
          style={{
            fontFamily: T.disp,
            fontSize: 19,
            fontWeight: 700,
            color: T.ink,
            margin: "0 0 14px",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          {icon && <span style={{ fontSize: 18 }}>{icon}</span>}
          {title}
        </h2>
      )}
      <div style={{ fontSize: 14.5, color: T.dim, lineHeight: 1.75 }}>{children}</div>
    </section>
  );
}
