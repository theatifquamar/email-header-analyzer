/* ============================================================
   Design tokens — Email Header Forensics premium theme
   ============================================================ */
export const T = {
  // Surface palette — deep navy/slate, not pure black, for a premium SaaS feel
  bg: "#0A0E1A",
  bgGrad: "linear-gradient(180deg, #0A0E1A 0%, #0C1120 40%, #0A0E1A 100%)",
  panel: "#111827",
  panel2: "#161F33",
  panelHover: "#1A2440",
  line: "#232E48",
  lineSoft: "#1A2338",

  // Text
  ink: "#EDF1FA",
  dim: "#9AABC9",
  faint: "#5F7093",

  // Brand / accent — warm amber against cool navy, signals "signal detected"
  accent: "#F5B841",
  accent2: "#FF8A4C",
  accentGrad: "linear-gradient(135deg, #F5B841 0%, #FF8A4C 100%)",

  // Semantic
  good: "#34D399",
  goodSoft: "#1B3A30",
  warn: "#F5B841",
  warnSoft: "#3A2E14",
  bad: "#FB7185",
  badSoft: "#3A1B24",
  info: "#7DB4F5",
  infoSoft: "#182A44",

  // Verdict gradient anchors (legit → malicious)
  verdictGrad: {
    "Legitimate": "linear-gradient(135deg, #34D399, #22B67F)",
    "Likely Legitimate": "linear-gradient(135deg, #8FE1B8, #34D399)",
    "Suspicious": "linear-gradient(135deg, #F5B841, #F59E4C)",
    "Likely Malicious": "linear-gradient(135deg, #FF8A4C, #FB7185)",
    "Malicious": "linear-gradient(135deg, #FB7185, #E11D48)",
  },

  // Type
  mono: "ui-monospace, 'Cascadia Code', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace",
  disp: "'Segoe UI', 'Avenir Next', 'Helvetica Neue', system-ui, sans-serif",
  body: "system-ui, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif",

  // Elevation
  shadowSm: "0 1px 2px rgba(0,0,0,0.35)",
  shadowMd: "0 4px 16px rgba(0,0,0,0.35), 0 1px 3px rgba(0,0,0,0.3)",
  shadowLg: "0 12px 40px rgba(0,0,0,0.45), 0 2px 8px rgba(0,0,0,0.3)",
  shadowGlow: "0 0 0 1px rgba(245,184,65,0.15), 0 8px 30px rgba(245,184,65,0.08)",

  // Radii
  r1: 6,
  r2: 10,
  r3: 14,
  r4: 20,

  // Motion
  ease: "cubic-bezier(0.22, 1, 0.36, 1)",
};

export const VERDICT_COLOR = {
  Legitimate: T.good,
  "Likely Legitimate": "#8FE1B8",
  Suspicious: T.warn,
  "Likely Malicious": "#FF8A4C",
  Malicious: T.bad,
};

export const polColor = (p) => (p === "pos" ? T.good : p === "neg" ? T.bad : T.info);
export const polSym = (p) => (p === "pos" ? "＋" : p === "neg" ? "－" : "◦");
