import React from "react";
import { T } from "../theme.js";
import { PageShell, Section } from "../components/PageShell.jsx";

export function PolicyPage() {
  const p = { margin: "0 0 12px" };
  const ul = { margin: "0 0 12px", paddingLeft: 20 };
  const li = { marginBottom: 7 };
  const strong = { color: T.ink, fontWeight: 600 };

  return (
    <PageShell
      eyebrow="LEGAL"
      title="Legal & Acceptable Use Policy"
      subtitle="Please read this page before relying on Email Header Forensics for an investigation. It explains what the tool is for, what it cannot promise, and where responsibility sits."
    >
      <Section title="1. Purpose & intended use" icon="🎯">
        <p style={p}>
          Email Header Forensics is a defensive security utility built to help SOC analysts, incident
          responders, IT administrators, and security researchers triage email headers during
          phishing investigations and routine email security review. It is intended to be used:
        </p>
        <ul style={ul}>
          <li style={li}>By security professionals as part of a documented investigation workflow.</li>
          <li style={li}>To assist — not replace — human judgment and organizational escalation procedures.</li>
          <li style={li}>On headers the user has a legitimate right to analyze (their own mail, mail submitted to their organization's abuse/phishing mailbox, or mail they are authorized to investigate).</li>
        </ul>
        <p style={p}>
          You agree not to use this tool to analyze headers obtained without authorization, to
          facilitate surveillance of individuals without lawful basis, to circumvent an
          organization's security controls, or for any unlawful purpose. You are solely
          responsible for ensuring your use complies with your organization's policies and all
          applicable laws in your jurisdiction.
        </p>
      </Section>

      <Section title="2. No warranty — provided “as is”" icon="⚠️">
        <p style={p}>
          Email Header Forensics is provided <strong style={strong}>“as is” and “as available,” without warranty of
          any kind</strong>, express or implied, including but not limited to warranties of
          merchantability, fitness for a particular purpose, accuracy, completeness, non-infringement,
          or that the tool will be uninterrupted, secure, or error-free. The developer makes no
          representation that the analysis engine correctly identifies every phishing message,
          spoofing attempt, or authentication failure, or that it will never produce a false
          positive or false negative.
        </p>
      </Section>

      <Section title="3. Analysis results are advisory only" icon="🧭">
        <p style={p}>
          Every verdict, confidence score, indicator, and recommendation produced by this tool is{" "}
          <strong style={strong}>advisory and probabilistic, not a determination of fact</strong>. Email
          header analysis is inherently limited: headers can be incomplete, forged below a
          trusted hop, or simply insufficient to reach certainty. The tool's own scoring is
          intentionally capped between 2% and 98% for exactly this reason — it never claims
          absolute proof of legitimacy or malice, and neither should you when reporting its output.
        </p>
        <p style={p}>
          Do not treat any verdict — including “Legitimate” or “Malicious” — as a substitute for
          your organization's incident response process, legal judgment, or a qualified
          professional's opinion where one is warranted.
        </p>
      </Section>

      <Section title="4. Limitation of liability" icon="🛡️">
        <p style={p}>
          To the maximum extent permitted by applicable law, the developer/owner of this
          application (Atif Quamar) shall not be liable for any direct, indirect, incidental,
          special, consequential, or exemplary damages — including but not limited to loss of
          data, loss of profits, business interruption, security incidents, missed detections,
          false positives/negatives, or any decision made or action taken (or not taken) in
          reliance on this tool's output — arising out of or in connection with the use, misuse,
          or inability to use this application, even if advised of the possibility of such
          damages.
        </p>
        <p style={p}>
          This limitation applies regardless of the legal theory asserted (contract, tort,
          negligence, strict liability, or otherwise) and applies to the fullest extent
          permitted where you are located.
        </p>
      </Section>

      <Section title="5. Privacy statement — what is and isn't stored" icon="🔒">
        <p style={p}><strong style={strong}>What is never stored, logged, or transmitted to any server:</strong></p>
        <ul style={ul}>
          <li style={li}>The raw email headers or message content you paste into the tool.</li>
          <li style={li}>Any parsed field — sender, recipient, subject, IP address, domain — extracted during analysis.</li>
          <li style={li}>The verdict, confidence score, evidence list, or exported report.</li>
          <li style={li}>Your answers to the interactive follow-up questions.</li>
        </ul>
        <p style={p}>
          All analysis runs entirely inside your browser tab, in memory (React state and a
          JavaScript cache). Nothing is written to localStorage, sessionStorage, IndexedDB, or
          cookies. Closing or reloading the tab permanently destroys everything. The application
          has no backend, no database, and no analytics or tracking scripts.
        </p>
        <p style={p}><strong style={strong}>What can leave your browser, only if you keep the optional feature enabled:</strong></p>
        <ul style={ul}>
          <li style={li}>
            IP addresses and domain names extracted from headers, sent to public
            DNS-over-HTTPS resolvers (dns.google, cloudflare-dns.com) to perform reverse-DNS,
            FCrDNS, ASN, MX, SPF, and DMARC lookups. Message content and analysis results are
            never included in these queries.
          </li>
          <li style={li}>
            The sender's domain name only, sent to public RDAP registration-data services
            (rdap.verisign.com for .com/.net, rdap.org for other TLDs) to determine domain
            registration age — a newly registered domain is one of the strongest phishing
            signals available. Message content is never included in these queries, and if a
            registry doesn't support RDAP for a given TLD, the check is simply marked
            unavailable rather than treated as suspicious.
          </li>
        </ul>
        <p style={p}>
          You can disable this feature at any time in the interface for fully offline analysis.
          A Content-Security-Policy enforced by your browser restricts this application's network
          access to only those named resolvers — no other destination is technically reachable
          from within the page.
        </p>
        <p style={p}>
          Standard web server / CDN access logs (visitor IP address, timestamp, requested file
          path) may be retained by whichever infrastructure hosts this application, independent
          of the application itself — this is normal for any website and is unrelated to the
          data you analyze.
        </p>
      </Section>

      <Section title="6. Recommendation: independently validate critical findings" icon="✅">
        <p style={p}>
          Before taking any consequential action — blocking a sender, quarantining messages
          organization-wide, resetting credentials, notifying a customer or executive, or
          filing an incident report — independently validate the tool's findings using
          authoritative sources: your mail platform's own delivery logs, DNS records queried
          directly, threat-intelligence platforms, and, where appropriate, direct out-of-band
          contact with the purported sender. This tool is a triage accelerant, not a final
          arbiter.
        </p>
      </Section>

      <Section title="7. No professional relationship created" icon="📄">
        <p style={p}>
          Use of this application does not create any consulting, advisory, employment, or other
          professional relationship between you and the developer. Nothing on this site
          constitutes legal, compliance, or professional security advice specific to your
          organization's circumstances.
        </p>
      </Section>

      <Section title="8. Intellectual property & open availability" icon="📦">
        <p style={p}>
          This application is made available to the cybersecurity community, including its
          source, for transparency and independent audit. Unless a separate license file states
          otherwise in the source repository, you may use, self-host, and modify the code for
          your own defensive security purposes. The developer retains no claim over your pasted
          data (none is ever received) and asserts no ownership over your analysis outputs.
        </p>
      </Section>

      <Section title="9. Changes to this policy" icon="🔄">
        <p style={p}>
          This policy may be updated as the tool evolves. Continued use of the application after
          changes are published constitutes acceptance of the revised policy. If you self-host
          this application, the version of this policy shipped with your deployment governs
          your instance.
        </p>
      </Section>

      <Section title="10. Contact" icon="✉️">
        <p style={{ margin: 0 }}>
          Questions about this policy or the tool can be directed to the developer via{" "}
          <a href="https://www.linkedin.com/in/theatifquamar/" target="_blank" rel="noreferrer" style={{ color: T.accent, fontWeight: 600 }}>
            LinkedIn
          </a>.
        </p>
      </Section>
    </PageShell>
  );
}
