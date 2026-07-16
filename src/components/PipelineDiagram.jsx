import React from "react";
import { T } from "../theme.js";

const STEPS = [
  { n: "01", t: "Paste headers", d: "Raw headers or full source; body discarded at first blank line", c: T.info },
  { n: "02", t: "Parse & unfold", d: "Received chain, Authentication-Results, From/Reply-To/Return-Path", c: T.info },
  { n: "03", t: "Authenticate", d: "SPF · DKIM · DMARC · alignment · ARC / compauth", c: T.accent },
  { n: "04", t: "Validate routing", d: "Timestamps · HELO/rDNS · relay length · ESP/gateway recognition", c: T.accent },
  { n: "05", t: "Enrich (optional)", d: "Live PTR · FCrDNS · ASN · MX/SPF/DMARC via DNS-over-HTTPS", c: T.accent2 },
  { n: "06", t: "Correlate evidence", d: "Every finding weighted +/− from a neutral baseline of 50", c: T.good },
  { n: "07", t: "Ask, if inconclusive", d: "Targeted context questions only in the 22–80 score band", c: T.good },
  { n: "08", t: "Score & verdict", d: "Capped 2–98 · mapped to 5 verdict bands", c: T.bad },
  { n: "09", t: "Report", d: "Executive summary · hop map · Markdown/PDF export", c: T.bad },
];

export function PipelineDiagram() {
  const w = 1180, colW = 250, gap = 26, cols = 3;
  const cardH = 118;
  const rows = Math.ceil(STEPS.length / cols);

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg viewBox={`0 0 ${w} ${rows * (cardH + gap) + 40}`} width="100%" style={{ minWidth: 720 }}>
        <defs>
          <marker id="hf-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
            <path d="M0,0 L8,3 L0,6 Z" fill={T.faint} />
          </marker>
        </defs>

        {STEPS.map((s, i) => {
          const col = i % cols;
          const row = Math.floor(i / cols);
          const ltr = row % 2 === 0;
          const c = ltr ? col : cols - 1 - col;
          const x = 20 + c * (colW + gap);
          const y = 20 + row * (cardH + gap);
          return (
            <g key={s.n}>
              <rect x={x} y={y} width={colW} height={cardH} rx={14} fill={T.panel2} stroke={T.line} strokeWidth="1.4" />
              <rect x={x} y={y} width={5} height={cardH} rx={2.5} fill={s.c} />
              <text x={x + 20} y={y + 30} fill={s.c} fontFamily={T.mono} fontSize="12" fontWeight="700">{s.n}</text>
              <text x={x + 20} y={y + 52} fill={T.ink} fontFamily={T.disp} fontSize="15.5" fontWeight="700">{s.t}</text>
              <foreignObject x={x + 20} y={y + 60} width={colW - 40} height={cardH - 65}>
                <div style={{ fontFamily: T.body, fontSize: 11.3, color: T.dim, lineHeight: 1.45 }}>{s.d}</div>
              </foreignObject>
            </g>
          );
        })}

        {/* connective arrows: snake left-to-right, then right-to-left on alternating rows */}
        {STEPS.slice(0, -1).map((_, i) => {
          const col = i % cols, row = Math.floor(i / cols);
          const ltr = row % 2 === 0;
          const c = ltr ? col : cols - 1 - col;
          const isRowEnd = col === cols - 1;
          const x = 20 + c * (colW + gap);
          const y = 20 + row * (cardH + gap);

          if (!isRowEnd) {
            return (
              <line
                key={i}
                x1={ltr ? x + colW : x}
                y1={y + cardH / 2}
                x2={ltr ? x + colW + gap : x - gap}
                y2={y + cardH / 2}
                stroke={T.faint}
                strokeWidth="2"
                markerEnd="url(#hf-arrow)"
              />
            );
          }
          const nextRow = row + 1;
          const nextLtr = nextRow % 2 === 0;
          const nextC = nextLtr ? 0 : cols - 1;
          const cx = 20 + c * (colW + gap) + colW / 2;
          const nx = 20 + nextC * (colW + gap) + colW / 2;
          const ny = 20 + nextRow * (cardH + gap);
          return (
            <path
              key={i}
              d={`M ${cx} ${y + cardH} C ${cx} ${y + cardH + gap / 2}, ${nx} ${ny - gap / 2}, ${nx} ${ny}`}
              stroke={T.faint}
              strokeWidth="2"
              fill="none"
              markerEnd="url(#hf-arrow)"
            />
          );
        })}
      </svg>
    </div>
  );
}
