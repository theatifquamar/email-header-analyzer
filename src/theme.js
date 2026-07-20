/* ============================================================
   Design tokens — Email Header Forensics premium theme

   Palette rationale: the brand/interactive color (violet/indigo) is
   deliberately NOT one of the four semantic verdict colors below, so an
   analyst can never mistake "this is just a button" for "this specific
   finding is concerning." An earlier revision used the same amber for
   both brand accent and the "Suspicious" verdict — fixed here.
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

  // Brand / accent — violet/indigo, reserved for interactive UI only
  // (buttons, links, logo, focus rings, active nav). Never reused as a
  // verdict color, so brand and "this is a warning" can't be confused.
  accent: "#8B7CF6",
  accent2: "#5B6EF5",
  accentGrad: "linear-gradient(135deg, #8B7CF6 0%, #5B6EF5 100%)",

  // Semantic verdict/status colors — each a distinct hue from the brand
  // and from each other, so color alone carries unambiguous meaning.
  good: "#34D399",
  goodSoft: "#1B3A30",
  warn: "#F2B84B",
  warnSoft: "#3A2E14",
  bad: "#FB7185",
  badSoft: "#3A1B24",
  info: "#38BDF8",
  infoSoft: "#122A38",

  // Verdict gradient anchors (legit → malicious) — built only from
  // semantic tones, never the brand accent.
  verdictGrad: {
    "Legitimate": "linear-gradient(135deg, #34D399, #22B67F)",
    "Likely Legitimate": "linear-gradient(135deg, #8FE1B8, #34D399)",
    "Suspicious": "linear-gradient(135deg, #F2B84B, #E8A23D)",
    "Likely Malicious": "linear-gradient(135deg, #F2925E, #FB7185)",
    "Malicious": "linear-gradient(135deg, #FB7185, #E11D48)",
  },

  // Type — self-hosted via @fontsource (same-origin, zero external
  // requests; font-src 'self' already covers this, no CSP change needed).
  // System-font fallbacks kept in case the bundled font fails to load.
  mono: "'JetBrains Mono', ui-monospace, 'Cascadia Code', 'SF Mono', Menlo, Consolas, monospace",
  disp: "'Space Grotesk', 'Segoe UI', 'Avenir Next', system-ui, sans-serif",
  body: "'Inter', system-ui, 'Segoe UI', Roboto, sans-serif",

  // Elevation
  shadowSm: "0 1px 2px rgba(0,0,0,0.35)",
  shadowMd: "0 4px 16px rgba(0,0,0,0.35), 0 1px 3px rgba(0,0,0,0.3)",
  shadowLg: "0 12px 40px rgba(0,0,0,0.45), 0 2px 8px rgba(0,0,0,0.3)",
  shadowGlow: "0 0 0 1px rgba(139,124,246,0.18), 0 8px 30px rgba(139,124,246,0.10)",

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
  "Likely Malicious": "#F2925E",
  Malicious: T.bad,
};

export const polColor = (p) => (p === "pos" ? T.good : p === "neg" ? T.bad : T.info);
export const polSym = (p) => (p === "pos" ? "＋" : p === "neg" ? "－" : "◦");
