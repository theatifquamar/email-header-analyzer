import React from "react";
import { T } from "../theme.js";
import { PageShell, Section } from "../components/PageShell.jsx";
import { PipelineDiagram } from "../components/PipelineDiagram.jsx";

function VerdictRow({ range, name, color, desc }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 14, padding: "12px 0", borderBottom: `1px solid ${T.line}55` }}>
      <div
        style={{
          fontFamily: T.mono,
          fontSize: 12,
          fontWeight: 700,
          color: "#0A0E1A",
          background: color,
          borderRadius: 999,
          padding: "3px 11px",
          flexShrink: 0,
          minWidth: 68,
          textAlign: "center",
        }}
      >
        {range}
      </div>
      <div>
        <div style={{ fontWeight: 700, color: T.ink, fontSize: 14.5 }}>{name}</div>
        <div style={{ fontSize: 13, color: T.dim, marginTop: 2, lineHeight: 1.5 }}>{desc}</div>
      </div>
    </div>
  );
}

function WeightRow({ label, weight, why }) {
  return (
    <div style={{ padding: "10px 0", borderBottom: `1px solid ${T.line}55` }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
        <span style={{ fontWeight: 600, color: T.ink, fontSize: 13.5 }}>{label}</span>
        <span style={{ fontFamily: T.mono, fontSize: 12, color: T.accent, flexShrink: 0 }}>{weight}</span>
      </div>
      <div style={{ fontSize: 12.5, color: T.dim, marginTop: 3, lineHeight: 1.5 }}>{why}</div>
    </div>
  );
}

export function HowItWorksPage() {
  return (
    <PageShell
      eyebrow="METHODOLOGY"
      title="How the analysis works"
      subtitle="From a pasted header block to a final, evidence-weighted verdict — every step below runs in your browser, in the order shown."
      wide
    >
      <Section title="The analysis pipeline" icon="🧬">
        <PipelineDiagram />
      </Section>

      <Section title="1 · Input & parsing" icon="📥">
        <p style={{ margin: "0 0 10px" }}>
          The tool accepts either a bare header block or a full message source pasted from your
          mail client. If a full message is pasted, everything after the first blank line (the
          message body) is discarded immediately and never parsed — this is what makes the
          "no content is analyzed, only transport metadata" guarantee true rather than aspirational.
        </p>
        <p style={{ margin: 0 }}>
          Folded header lines (continuation lines starting with a space or tab, common in{" "}
          <code style={{ fontFamily: T.mono }}>Received</code> and <code style={{ fontFamily: T.mono }}>DKIM-Signature</code> headers)
          are unfolded back into single logical lines before any field is extracted, so multi-line
          headers from any mail transfer agent parse correctly.
        </p>
      </Section>

      <Section title="2 · Authentication evaluation" icon="🔑">
        <p style={{ margin: "0 0 10px" }}>
          <strong style={{ color: T.ink }}>SPF</strong> is read from <code style={{ fontFamily: T.mono }}>Authentication-Results</code> or,
          when absent, a legacy <code style={{ fontFamily: T.mono }}>Received-SPF</code> header. Every result (pass, fail,
          softfail, neutral, none, temperror, permerror) is weighted differently — a hard fail is
          treated as a strong spoofing signal, while "none" is treated as merely inconclusive, not
          negative, since many legitimate small domains simply don't publish SPF.
        </p>
        <p style={{ margin: "0 0 10px" }}>
          <strong style={{ color: T.ink }}>DKIM</strong> verification results are likewise read from
          Authentication-Results; the tool also parses raw{" "}
          <code style={{ fontFamily: T.mono }}>DKIM-Signature</code> fields for the signing domain, but is explicit that it
          cannot cryptographically re-verify a signature without the message body — that would
          require the body hash, which a header-only tool by design never receives.
        </p>
        <p style={{ margin: 0 }}>
          <strong style={{ color: T.ink }}>DMARC</strong> combines both: its result and published policy
          (<code style={{ fontFamily: T.mono }}>p=reject/quarantine/none</code>) are parsed, and — independently —
          the tool computes whether the SPF domain and DKIM signing domain are organizationally
          aligned with the visible From: domain. This alignment check catches a pattern DMARC
          alone can miss: a message that passes SPF/DKIM for an unrelated domain while displaying
          a trusted brand name.
        </p>
      </Section>

      <Section title="3 · Routing & transport validation" icon="🛰️">
        <p style={{ margin: "0 0 10px" }}>
          Every <code style={{ fontFamily: T.mono }}>Received</code> header is parsed into a hop: source host, IP,
          reverse DNS (if present in the header), receiving host, TLS usage, and timestamp. Hops
          are reassembled into chronological order (origin → delivery) regardless of the order
          they appear in the raw header block.
        </p>
        <p style={{ margin: "0 0 10px" }}>
          <strong style={{ color: T.ink }}>Timestamp forensics</strong> checks that hop times increase
          monotonically, allowing a small clock-skew tolerance; a reversal beyond that tolerance
          is a concrete signal of a forged or reordered Received header. The Date: header is also
          compared against final delivery time — a large mismatch, or a Date in the future, is flagged.
        </p>
        <p style={{ margin: "0 0 10px" }}>
          <strong style={{ color: T.ink }}>HELO/EHLO validation</strong> compares the hostname a server
          announced at connection time against its reverse DNS name; a mismatch at the origin hop
          is noted as a configuration anomaly or identity-masking attempt.
        </p>
        <p style={{ margin: 0 }}>
          <strong style={{ color: T.ink }}>Provider recognition</strong> matches hop hostnames against a
          registry of 20+ known email service providers and secure email gateways (Google, Microsoft
          365, SendGrid, Mailchimp, Amazon SES, Proofpoint, Mimecast, and others). This is what lets
          the engine correctly treat a security-gateway hop as expected inline filtering rather than
          suspicious forwarding, and an ESP's own bounce domain as normal rather than a spoofing signal.
        </p>
      </Section>

      <Section title="4 · Optional live enrichment" icon="🌐">
        <p style={{ margin: "0 0 10px" }}>
          When enabled, the tool performs live DNS-over-HTTPS lookups directly from your browser:
          reverse DNS (PTR) for each public origin IP, forward-confirmation of that PTR name back
          to the IP (FCrDNS), ASN/organization/country via Team Cymru's DNS-based lookup, and MX,
          SPF, and DMARC records for the sender's domain.
        </p>
        <p style={{ margin: 0 }}>
          This step is <strong style={{ color: T.ink }}>off by default</strong> and opt-in specifically because it is the one place data
          leaves the browser at all (as IPs/domains only, to public resolvers, never message
          content). If disabled or unreachable, the engine degrades gracefully — it uses only
          header-recorded evidence and explicitly lists the missing checks as uncertainties rather
          than silently assuming a result.
        </p>
      </Section>

      <Section title="5 · Evidence correlation & weighting" icon="⚖️">
        <p style={{ margin: "0 0 14px" }}>
          Every message starts at a neutral baseline of <strong style={{ color: T.ink }}>50</strong>. Each
          independent finding — positive or negative — adjusts the score by a fixed weight. No
          single indicator ever decides the verdict alone; the final score is the sum of everything
          the engine found. Representative weights:
        </p>
        <WeightRow label="DMARC fail against an enforcing (reject) policy" weight="−16" why="The domain owner explicitly asked receivers to reject unaligned mail; failing that is one of the strongest available spoofing signals." />
        <WeightRow label="SPF hard fail" weight="−16" why="The sending IP is explicitly disallowed by the domain's own published policy." />
        <WeightRow label="DKIM / DMARC pass" weight="+12 to +14" why="Cryptographic and policy-level proof the visible sender authorized this exact message." />
        <WeightRow label="Residential/dynamic-IP-style origin" weight="−8" why="Real mail servers almost never sit on consumer ISP address space; this pattern dominates botnet-relayed phishing." />
        <WeightRow label="Missing Message-ID" weight="−6" why="Nearly universal in legitimate MTAs; absence suggests a crude or scripted sending tool." />
        <WeightRow label="Recognized ESP/gateway infrastructure on path" weight="+3 to +8" why="Matches documented, expected routing behavior for that provider rather than ad hoc forwarding." />
        <p style={{ margin: "14px 0 0" }}>
          Weights were set by how strongly each signal discriminates between legitimate and
          malicious mail in practice, not by how easy each check is to compute. Authentication
          results and DNS-verifiable facts (SPF/DKIM/DMARC, FCrDNS) carry the heaviest weights
          because they are the hardest for an attacker to fake convincingly. Softer heuristics —
          display-name patterns, TLD reputation, scripted-mailer signatures — carry smaller weights
          and are treated as corroborating context, not standalone proof.
        </p>
      </Section>

      <Section title="6 · Interactive context questions" icon="❓">
        <p style={{ margin: 0 }}>
          When the running score lands in the inconclusive band (roughly 22–80) — or when header
          evidence alone is too sparse to evaluate — the tool asks a small number of targeted
          questions: was the message expected, is the sender known, did the recipient interact
          with content, was it internal or external, does it use urgency or payment pressure? Each
          answer adjusts the score exactly like a header-derived finding, with its own stated
          weight and rationale, and the panel explicitly says when header evidence is already
          strong enough that these answers would not move the verdict.
        </p>
      </Section>

      <Section title="7 · Final score & verdict bands" icon="🏁">
        <p style={{ margin: "0 0 14px" }}>
          The final score is clamped between 2 and 98 — never 0 or 100 — because header-only
          evidence can never mathematically support absolute certainty. That score maps to one of
          five verdict bands:
        </p>
        <VerdictRow range="88–98" name="Legitimate" color={T.good} desc="Strong authenticated proof across SPF/DKIM/DMARC with clean alignment and routing; no material anomalies." />
        <VerdictRow range="70–87" name="Likely Legitimate" color="#8FE1B8" desc="Evidence mostly supports legitimacy but with minor unresolved anomalies or incomplete authentication." />
        <VerdictRow range="45–69" name="Suspicious" color={T.warn} desc="Mixed or insufficient evidence; genuinely inconclusive without further context or the message body." />
        <VerdictRow range="22–44" name="Likely Malicious" color="#FF8A4C" desc="Multiple negative indicators outweigh any positive evidence; treat as high-priority for verification." />
        <VerdictRow range="2–21" name="Malicious" color={T.bad} desc="Strong, corroborated evidence of spoofing or forgery across authentication and routing checks." />
      </Section>

      <Section title="8 · Reporting" icon="📄">
        <p style={{ margin: 0 }}>
          The final view assembles a plain-language executive summary, the full positive/negative/
          uncertainty evidence lists, the scoring ledger showing the arithmetic from baseline to
          final score, the chain-of-custody hop map, and a recommended-action list tailored to the
          verdict band. All of it exports as Markdown or a print-optimized PDF that mirrors the
          on-screen report.
        </p>
      </Section>
    </PageShell>
  );
}
