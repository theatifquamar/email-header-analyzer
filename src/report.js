import { QUESTIONS } from "./engine.js";

/* ============================================================
   Report builders — Markdown export + recommended actions +
   executive summary text. Pure functions, no side effects other
   than the Blob download triggered by the caller.
   ============================================================ */

/* ---------------- Report builders ---------------- */
export function buildMarkdown(res, answers, dns) {
  const { score, verdict } = res.scored;
  const pos = res.evidence.filter((e) => e.pol === "pos");
  const neg = res.evidence.filter((e) => e.pol === "neg");
  const notes = res.evidence.filter((e) => e.pol === "note");
  const lines = [];
  lines.push(`# Email Header Analysis Report`, ``, `**Generated:** ${new Date().toISOString()} · Email Header Forensics (in-memory analysis, no data retained)`, ``);
  lines.push(`## Executive summary`, ``, `**Verdict: ${verdict}** — confidence score **${score}/100**.`, ``);
  lines.push(res.summary, ``);
  lines.push(`## Message identity`, ``, `| Field | Value |`, `|---|---|`,
    `| From | ${res.meta.fromRaw || "—"} |`,
    `| Return-Path | ${res.meta.returnPath || "—"} |`,
    `| Reply-To | ${res.meta.replyTo || "—"} |`,
    `| Subject | ${res.meta.subject || "—"} |`,
    `| Message-ID | ${res.meta.messageId || "—"} |`,
    `| Date | ${res.meta.dateHdr || "—"} |`, ``);
  lines.push(`## Transport path (origin → delivery)`, ``);
  res.hops.forEach((hopI, i) => {
    const d = dns[hopI.fromIP] || {};
    lines.push(`${i + 1}. **${hopI.fromHost || "unknown"}** ${hopI.fromIP ? `[${hopI.fromIP}]` : ""} → ${hopI.byHost || "?"}${hopI.tls ? " (TLS)" : ""}${hopI.date ? ` — ${hopI.date.toISOString()}` : ""}${hopI.provider ? ` — ${hopI.provider.name}` : ""}${d.asn ? ` — AS${d.asn.asn} ${d.asn.org || ""}` : ""}`);
  });
  lines.push(``, `## Positive indicators`, ``, ...(pos.length ? pos.map((e) => `- **${e.label}** (+${e.w}): ${e.detail}`) : ["- None identified."]));
  lines.push(``, `## Negative indicators`, ``, ...(neg.length ? neg.map((e) => `- **${e.label}** (−${e.w}): ${e.detail}`) : ["- None identified."]));
  lines.push(``, `## Observations & uncertainties`, ``, ...(notes.length ? notes.map((e) => `- ${e.label}: ${e.detail}`) : ["- None."]));
  lines.push(``, `## Analyst context provided`, ``, ...QUESTIONS.map((q) => `- ${q.q} **${answers[q.id] || "Not answered"}**`));
  lines.push(``, `## Limitations`, ``, `- Header-only analysis: DKIM signatures cannot be cryptographically re-verified without the message body; results rely on the receiving server's recorded Authentication-Results.`);
  lines.push(`- Received headers below the first trusted hop can be forged by the sender.`);
  lines.push(res.dnsLive ? `- Live DNS lookups (PTR/FCrDNS/ASN/MX/SPF/DMARC) were performed via DNS-over-HTTPS at analysis time.` : `- Live DNS lookups were unavailable or disabled; rDNS/FCrDNS/ASN findings rely solely on header contents.`);
  lines.push(``, `## Recommended actions`, ``, ...res.actions.map((a) => `- ${a}`));
  return lines.join("\n");
}

export function recommendedActions(verdict, answers, res) {
  const a = [];
  if (verdict === "Malicious" || verdict === "Likely Malicious") {
    a.push("Quarantine the message and search the mail platform for other recipients of the same sender, subject, or Message-ID pattern.");
    a.push("Block the origin IP(s) and sender domain at the email gateway; add IOCs to the SIEM watchlist.");
    if (answers.interact === "Yes") a.push("PRIORITY: recipient interacted with content — isolate/scan the endpoint and force credential reset with session revocation for the recipient.");
    a.push("Submit origin IPs and any URLs/attachments to sandbox and reputation services; preserve the original .eml as evidence.");
    a.push("If a brand or executive was impersonated, notify the impersonated party and consider a user-awareness bulletin.");
  } else if (verdict === "Suspicious") {
    a.push("Obtain the full message body, URLs, and attachment hashes to close the remaining evidence gaps before final disposition.");
    a.push("Verify the sender out-of-band (phone/known-good address) before any action requested by the email is taken.");
    if (answers.interact === "Yes") a.push("Recipient interacted with content — review endpoint telemetry and authentication logs as a precaution.");
    a.push("Check gateway logs for similar messages to other users; a single sample may be part of a campaign.");
  } else {
    a.push("No immediate response action required based on header evidence.");
    a.push("If the recipient still finds the content unusual, verify the request out-of-band — passing authentication does not rule out a compromised legitimate account.");
    if (res.evidence.some((e) => e.pol === "neg")) a.push("Note the minor anomalies recorded above in the ticket for future correlation.");
  }
  a.push("Retain this report in your case system; the analyzer itself keeps nothing.");
  return a;
}

export function buildSummary(res, scored) {
  const m = res.meta;
  const auth = res.auth;
  const bits = [];
  bits.push(`Message purports to be from ${m.fromRaw || "an unspecified sender"}${m.subject ? ` with subject "${m.subject}"` : ""}.`);
  const spf = auth.spf?.result || res.rspf?.result || "not evaluated";
  const dkim = auth.dkim.length ? auth.dkim.map((d) => d.result).join("/") : m.dkimSigs.length ? "present, unverified" : "absent";
  const dmarc = auth.dmarc?.result || "not evaluated";
  bits.push(`Authentication: SPF ${spf}, DKIM ${dkim}, DMARC ${dmarc}.`);
  bits.push(`The transport path shows ${res.hops.length} hop${res.hops.length === 1 ? "" : "s"}${res.hops.some((h) => h.provider) ? `, transiting recognized infrastructure (${[...new Set(res.hops.filter((h) => h.provider).map((h) => h.provider.name))].join(", ")})` : ""}.`);
  const negs = res.evidence.filter((e) => e.pol === "neg");
  if (negs.length) bits.push(`Key concerns: ${negs.slice(0, 3).map((e) => e.label.toLowerCase()).join("; ")}.`);
  bits.push(`Correlating all evidence yields a confidence score of ${scored.score}/100 → ${scored.verdict}. This assessment is probabilistic: header evidence alone cannot establish absolute certainty, and any listed uncertainties should be resolved before final disposition.`);
  return bits.join(" ");
}
