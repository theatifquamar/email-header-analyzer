import React, { useState, useMemo, useCallback } from "react";
import { T, VERDICT_COLOR, polColor } from "../theme.js";
import {
  parseHeaders, analyzeStatic, scoreEvidence, isPrivateIP, orgDomain,
  ptrLookup, fcrdns, asnLookup, doh, domainAgeInfo, dnsCache, QUESTIONS,
  SAMPLE_LEGIT, SAMPLE_SUS,
} from "../engine.js";
import { buildMarkdown, buildJson, recommendedActions, buildSummary } from "../report.js";
import { Collapsible, EvidenceRow, Tag } from "../components/Primitives.jsx";
import { HopRail } from "../components/HopRail.jsx";

export function AnalyzerPage() {
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState(null);
  const [answers, setAnswers] = useState({});
  const [dns, setDns] = useState({});
  const [dnsLive, setDnsLive] = useState(null);
  const [useDns, setUseDns] = useState(false);
  const [busy, setBusy] = useState(false);

  const analyze = useCallback(async () => {
    if (!raw.trim()) return;
    setBusy(true);
    setAnswers({});
    const h = parseHeaders(raw);
    const base = analyzeStatic(h);
    const res = { ...base, evidence: base.ev, dnsLive: false };
    setDns({});
    setResult({ ...res, scored: scoreEvidence(res.evidence), summary: "", actions: [] });

    const dnsMap = {};
    let live = false;
    if (useDns) {
      const publicIPs = [...new Set(base.hops.map((x) => x.fromIP).filter((ip) => ip && !isPrivateIP(ip)))].slice(0, 6);
      for (const ip of publicIPs) {
        const ptr = await ptrLookup(ip);
        if (ptr !== null) live = true;
        const entry = { ptr: ptr === null ? undefined : ptr };
        if (Array.isArray(ptr) && ptr.length) entry.fcrdns = await fcrdns(ip, ptr);
        const asn = await asnLookup(ip);
        if (asn) entry.asn = asn;
        dnsMap[ip] = entry;
      }
      if (base.meta.fromDom) {
        const mx = await doh(base.meta.fromDom, "MX");
        const spfTxt = await doh(base.meta.fromDom, "TXT");
        const dmarcTxt = await doh("_dmarc." + orgDomain(base.meta.fromDom), "TXT");
        if (mx !== null) live = true;
        dnsMap.__domain = {
          mx: mx || [],
          spf: (spfTxt || []).find((t) => /^v=spf1/i.test(t)) || null,
          dmarc: (dmarcTxt || []).find((t) => /^v=DMARC1/i.test(t)) || null,
          available: mx !== null,
        };
        const age = await domainAgeInfo(orgDomain(base.meta.fromDom));
        if (age) { dnsMap.__domainAge = age; live = true; }
      }
    }

    const ev = [...base.ev];
    const origin = base.hops.find((x) => x.isOrigin);
    if (live) {
      if (origin?.fromIP && dnsMap[origin.fromIP]) {
        const d = dnsMap[origin.fromIP];
        if (Array.isArray(d.ptr) && d.ptr.length === 0) ev.push({ pol: "neg", w: 5, label: "Origin IP has no PTR record (live lookup)", detail: `${origin.fromIP} resolves to no reverse DNS name — atypical for legitimate mail servers.`, cat: "dns" });
        if (d.fcrdns?.confirmed) ev.push({ pol: "pos", w: 5, label: "FCrDNS confirmed for origin", detail: `${origin.fromIP} ⇄ ${d.fcrdns.name} — forward-confirmed reverse DNS matches.`, cat: "dns" });
        else if (d.fcrdns && d.fcrdns.confirmed === false) ev.push({ pol: "neg", w: 4, label: "FCrDNS failed for origin", detail: `PTR name does not resolve back to ${origin.fromIP}.`, cat: "dns" });
        if (d.asn?.org && /(digitalocean|ovh|hetzner|contabo|vultr|linode|hosting|vps|colocat)/i.test(d.asn.org) && !base.hops.some((x) => x.provider)) {
          ev.push({ pol: "note", w: -2, label: "Origin in generic hosting/VPS space", detail: `AS${d.asn.asn} (${d.asn.org}). Legitimate senders use it too, but throwaway phishing infrastructure concentrates here.`, cat: "dns" });
        }
      }
      const dd = dnsMap.__domain;
      if (dd?.available) {
        if (!dd.mx.length) ev.push({ pol: "neg", w: 5, label: "Sender domain has no MX records", detail: `${base.meta.fromDom} cannot receive mail — send-only domains that can't receive replies are a phishing hallmark.`, cat: "dns" });
        else ev.push({ pol: "pos", w: 2, label: "Sender domain has MX records", detail: `${base.meta.fromDom} operates receiving mail infrastructure.`, cat: "dns" });
        if (dd.dmarc) {
          const p = (dd.dmarc.match(/p=(\w+)/i) || [])[1];
          ev.push({ pol: "pos", w: p && /reject|quarantine/i.test(p) ? 3 : 1, label: `Sender publishes DMARC (p=${p || "none"})`, detail: p && /reject|quarantine/i.test(p) ? "Enforcing policy — spoofing this domain should be blocked by compliant receivers, which strengthens a DMARC pass and sharpens a fail." : "Monitoring-only policy; spoofed mail is not blocked by receivers.", cat: "dns" });
        } else ev.push({ pol: "note", w: -2, label: "Sender publishes no DMARC record", detail: `_dmarc.${orgDomain(base.meta.fromDom)} not found — the domain is easier to spoof and alignment can't be enforced.`, cat: "dns" });
        if (!dd.spf) ev.push({ pol: "note", w: -2, label: "No SPF record published (live lookup)", detail: `${base.meta.fromDom} publishes no v=spf1 record.`, cat: "dns" });
      }
      if (base.meta.fromDom) {
        const age = dnsMap.__domainAge;
        if (age) {
          const yrs = (age.ageDays / 365).toFixed(1);
          if (age.ageDays < 7) {
            ev.push({ pol: "neg", w: 14, label: "Sender domain registered within the last week", detail: `${base.meta.fromDom} was registered ${age.ageDays} day${age.ageDays === 1 ? "" : "s"} ago${age.registrar ? ` via ${age.registrar}` : ""}. Brand-new domains sending mail — especially urgent or payment-related mail — are one of the strongest phishing signals available.`, cat: "dns" });
          } else if (age.ageDays < 30) {
            ev.push({ pol: "neg", w: 9, label: "Sender domain registered within the last month", detail: `${base.meta.fromDom} was registered ${age.ageDays} days ago. Legitimate correspondence from a brand-new domain is uncommon; verify independently.`, cat: "dns" });
          } else if (age.ageDays < 90) {
            ev.push({ pol: "neg", w: 4, label: "Sender domain registered within the last 3 months", detail: `${base.meta.fromDom} is ${age.ageDays} days old. Mildly elevated risk — many legitimate new businesses fall in this range too.`, cat: "dns" });
          } else if (age.ageDays > 365) {
            ev.push({ pol: "pos", w: 3, label: "Sender domain has an established registration history", detail: `${base.meta.fromDom} was registered ${yrs} years ago (${age.created.toISOString().slice(0, 10)}). Long-standing domains are less commonly used for disposable phishing infrastructure.`, cat: "dns" });
          } else {
            ev.push({ pol: "note", w: 0, label: "Sender domain registration age is unremarkable", detail: `${base.meta.fromDom} is ${age.ageDays} days old — neither newly registered nor long-established.`, cat: "dns" });
          }
        } else {
          ev.push({ pol: "note", w: 0, label: "Domain age unavailable", detail: `No RDAP registration data found for ${base.meta.fromDom} — either the registry doesn't yet support RDAP for this TLD, or the lookup was blocked. Not treated as a negative signal.`, cat: "dns" });
        }
      }
    }

    const scored = scoreEvidence(ev);
    const final = { ...base, evidence: ev, scored, dnsLive: live };
    final.summary = buildSummary(final, scored);
    final.actions = recommendedActions(scored.verdict, {}, final);
    setDns(dnsMap);
    setDnsLive(useDns ? live : false);
    setResult(final);
    setBusy(false);
  }, [raw, useDns]);

  const merged = useMemo(() => {
    if (!result) return null;
    const extra = [];
    for (const q of QUESTIONS) {
      const ans = answers[q.id];
      const adj = ans && q.adj[ans];
      if (adj) extra.push({ ...adj, cat: "context" });
    }
    const evidence = [...result.evidence, ...extra];
    const scored = scoreEvidence(evidence);
    const r = { ...result, evidence, scored };
    r.summary = buildSummary(r, scored);
    r.actions = recommendedActions(scored.verdict, answers, r);
    return r;
  }, [result, answers]);

  const needQuestions = merged && ((merged.scored.score >= 30 && merged.scored.score <= 80) || (!merged.auth.spf && !merged.rspf));
  const answeredCount = Object.values(answers).filter(Boolean).length;

  const exportMd = () => {
    const md = buildMarkdown(merged, answers, dns);
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `header-analysis-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const exportJson = () => {
    const data = buildJson(merged, answers, dns);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `header-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const pos = merged?.evidence.filter((e) => e.pol === "pos") || [];
  const neg = merged?.evidence.filter((e) => e.pol === "neg") || [];
  const notes = merged?.evidence.filter((e) => e.pol === "note") || [];
  const verdictBg = merged ? T.verdictGrad[merged.scored.verdict] : null;

  return (
    <main
      style={{
        maxWidth: 1280,
        margin: "0 auto",
        padding: "26px 22px 70px",
        display: "grid",
        gridTemplateColumns: "minmax(300px, 400px) 1fr",
        gap: 24,
        alignItems: "start",
      }}
    >
      {/* ===== Left: input & context ===== */}
      <div className="no-print" style={{ display: "flex", flexDirection: "column", gap: 16, position: "sticky", top: 78 }}>
        <div className="hf-card" style={{ border: `1px solid ${T.line}`, borderRadius: T.r3, background: T.panel, padding: 20, boxShadow: T.shadowMd }}>
          <div style={{ fontFamily: T.disp, fontWeight: 700, fontSize: 15.5, marginBottom: 5, display: "flex", alignItems: "center", gap: 8 }}>
            <span>📋</span> Paste raw headers
          </div>
          <div style={{ fontSize: 12.5, color: T.dim, marginBottom: 12, lineHeight: 1.55 }}>
            Full message source is fine — the body is discarded at the first blank line. Everything is
            analyzed in this tab's memory and vanishes when you leave.
          </div>
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            placeholder={"Received: from ...\nAuthentication-Results: ...\nFrom: ..."}
            style={{
              width: "100%",
              height: 220,
              background: "#070A13",
              color: T.ink,
              border: `1px solid ${T.line}`,
              borderRadius: T.r2,
              padding: 13,
              fontFamily: T.mono,
              fontSize: 12,
              lineHeight: 1.6,
              resize: "vertical",
              transition: `border-color .15s ${T.ease}`,
            }}
          />
          <label style={{ display: "flex", gap: 9, alignItems: "flex-start", margin: "12px 0", fontSize: 12.5, color: T.dim, cursor: "pointer" }}>
            <input type="checkbox" checked={useDns} onChange={(e) => setUseDns(e.target.checked)} style={{ marginTop: 2, accentColor: T.accent }} />
            <span>
              <strong style={{ color: T.ink }}>Off by default (privacy-first).</strong> Enable live DNS
              enrichment (PTR, FCrDNS, ASN, MX, SPF, DMARC) via DNS-over-HTTPS. Sends only IPs and domain
              names to the resolver — never message content. Leave unchecked for fully offline analysis.
            </span>
          </label>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button
              onClick={analyze}
              disabled={busy || !raw.trim()}
              style={{
                background: T.accentGrad,
                color: "#0A0E1A",
                border: "none",
                borderRadius: T.r2,
                padding: "11px 20px",
                fontFamily: T.disp,
                fontWeight: 700,
                fontSize: 13.8,
                cursor: raw.trim() ? "pointer" : "not-allowed",
                opacity: raw.trim() ? 1 : 0.5,
                boxShadow: raw.trim() ? T.shadowGlow : "none",
                transition: `transform .12s ${T.ease}`,
              }}
            >
              {busy ? "Analyzing…" : "Analyze headers"}
            </button>
            <button
              onClick={() => { setRaw(""); setResult(null); setAnswers({}); setDns({}); dnsCache.clear(); }}
              style={{ background: "none", color: T.dim, border: `1px solid ${T.line}`, borderRadius: T.r2, padding: "11px 16px", fontSize: 12.5, cursor: "pointer" }}
            >
              Clear everything
            </button>
          </div>
          <div style={{ display: "flex", gap: 14, marginTop: 12 }}>
            <button onClick={() => setRaw(SAMPLE_LEGIT)} style={{ background: "none", border: "none", color: T.info, fontSize: 11.5, fontFamily: T.mono, cursor: "pointer", padding: 0 }}>load legit sample</button>
            <button onClick={() => setRaw(SAMPLE_SUS)} style={{ background: "none", border: "none", color: T.info, fontSize: 11.5, fontFamily: T.mono, cursor: "pointer", padding: 0 }}>load phishing sample</button>
          </div>
        </div>

        {merged && needQuestions && (
          <div className="hf-card" style={{ border: `1px solid ${T.accent}44`, borderRadius: T.r3, background: T.panel, padding: 20, boxShadow: T.shadowMd }}>
            <div style={{ fontFamily: T.disp, fontWeight: 700, fontSize: 14.5, color: T.accent, display: "flex", alignItems: "center", gap: 7 }}>
              <span>🧩</span> Header evidence isn't conclusive
            </div>
            <div style={{ fontSize: 12.5, color: T.dim, margin: "5px 0 14px", lineHeight: 1.5 }}>
              These answers materially change the assessment. Answers stay in memory with everything else.
            </div>
            {QUESTIONS.map((q) => (
              <div key={q.id} style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 12.5, marginBottom: 7, color: T.ink }}>{q.q}</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {q.opts.map((o) => (
                    <button
                      key={o}
                      onClick={() => setAnswers((a) => ({ ...a, [q.id]: a[q.id] === o ? null : o }))}
                      style={{
                        padding: "6px 13px",
                        borderRadius: 999,
                        fontSize: 12,
                        fontFamily: T.mono,
                        cursor: "pointer",
                        border: `1px solid ${answers[q.id] === o ? T.accent : T.line}`,
                        background: answers[q.id] === o ? T.accentGrad : "transparent",
                        color: answers[q.id] === o ? "#0A0E1A" : T.dim,
                        fontWeight: answers[q.id] === o ? 700 : 400,
                        transition: `all .12s ${T.ease}`,
                      }}
                    >
                      {o}
                    </button>
                  ))}
                </div>
              </div>
            ))}
            <div style={{ fontSize: 11, fontFamily: T.mono, color: T.faint }}>{answeredCount}/{QUESTIONS.length} answered — score updates live</div>
          </div>
        )}
        {merged && !needQuestions && (
          <div style={{ border: `1px solid ${T.line}`, borderRadius: T.r3, background: T.panel, padding: 16, fontSize: 12.5, color: T.dim, lineHeight: 1.55 }}>
            Header evidence is strong enough that recipient context wouldn't change the verdict band, so no
            follow-up questions are needed. You can still document context in your ticket.
          </div>
        )}
      </div>

      {/* ===== Right: results ===== */}
      <div className="print-area">
        {!merged && (
          <div style={{ border: `1px dashed ${T.line}`, borderRadius: T.r3, padding: "70px 30px", textAlign: "center", color: T.faint, background: "radial-gradient(circle at 50% 0%, rgba(245,184,65,0.05), transparent 60%)" }}>
            <div style={{ fontFamily: T.disp, fontSize: 21, fontWeight: 700, color: T.dim, marginBottom: 10 }}>Awaiting evidence</div>
            <div style={{ fontSize: 13.5, maxWidth: 480, margin: "0 auto", lineHeight: 1.65 }}>
              Paste headers on the left. The analyzer reconstructs the transport chain, validates
              SPF/DKIM/DMARC and alignment, checks timestamps, recognizes legitimate ESP and gateway
              infrastructure, and correlates everything into an evidence-weighted verdict.
            </div>
          </div>
        )}

        {merged && (
          <>
            {/* print-only masthead: browser print omits page chrome, so restate identity here */}
            <div className="print-header" style={{ display: "none", marginBottom: 18 }}>
              <div style={{ fontFamily: T.disp, fontWeight: 700, fontSize: 20 }}>EMAIL HEADER FORENSICS — Analysis Report</div>
              <div style={{ fontFamily: T.mono, fontSize: 11, color: T.dim, marginTop: 4 }}>
                Generated {new Date().toISOString()} · analyzed entirely in-browser, nothing retained · by Atif Quamar
              </div>
            </div>

            {/* Verdict panel */}
            <div
              className="hf-card"
              style={{
                border: `1px solid ${VERDICT_COLOR[merged.scored.verdict]}55`,
                borderRadius: T.r3,
                background: `linear-gradient(160deg, ${VERDICT_COLOR[merged.scored.verdict]}1F, ${T.panel} 55%)`,
                padding: "24px 26px",
                marginBottom: 16,
                boxShadow: T.shadowLg,
              }}
            >
              <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "center" }}>
                <div>
                  <div style={{ fontFamily: T.mono, fontSize: 11, color: T.dim, letterSpacing: 1.2, fontWeight: 600 }}>VERDICT</div>
                  <div
                    style={{
                      fontFamily: T.disp, fontSize: 32, fontWeight: 700, lineHeight: 1.15,
                      background: verdictBg, WebkitBackgroundClip: "text", backgroundClip: "text", color: "transparent",
                    }}
                  >
                    {merged.scored.verdict}
                  </div>
                </div>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontFamily: T.mono, fontSize: 11, color: T.dim, marginBottom: 6 }}>
                    <span>confidence in legitimacy</span><span style={{ color: T.ink, fontWeight: 700 }}>{merged.scored.score}/100</span>
                  </div>
                  <div style={{ height: 9, borderRadius: 99, background: "#070A13", overflow: "hidden", border: `1px solid ${T.line}` }}>
                    <div style={{ width: `${merged.scored.score}%`, height: "100%", background: verdictBg, transition: `width .4s ${T.ease}` }} />
                  </div>
                  <div style={{ fontSize: 11, color: T.faint, marginTop: 7, fontFamily: T.mono }}>
                    capped at 2–98: header evidence alone never supports absolute certainty
                  </div>
                </div>
                <div className="no-print" style={{ display: "flex", gap: 8 }}>
                  <button onClick={exportMd} style={{ background: T.panel2, color: T.ink, border: `1px solid ${T.line}`, borderRadius: T.r2, padding: "10px 15px", fontSize: 12.5, cursor: "pointer", fontFamily: T.mono, fontWeight: 600 }}>↓ Markdown</button>
                  <button onClick={exportJson} style={{ background: T.panel2, color: T.ink, border: `1px solid ${T.line}`, borderRadius: T.r2, padding: "10px 15px", fontSize: 12.5, cursor: "pointer", fontFamily: T.mono, fontWeight: 600 }}>↓ JSON</button>
                  <button onClick={() => window.print()} style={{ background: T.panel2, color: T.ink, border: `1px solid ${T.line}`, borderRadius: T.r2, padding: "10px 15px", fontSize: 12.5, cursor: "pointer", fontFamily: T.mono, fontWeight: 600 }}>↓ PDF</button>
                </div>
              </div>
              <p style={{ fontSize: 13.8, color: T.ink, lineHeight: 1.7, margin: "16px 0 0" }}>{merged.summary}</p>
              {dnsLive === false && useDns && (
                <div style={{ marginTop: 10, fontSize: 11.5, fontFamily: T.mono, color: T.warn }}>
                  ⚠ Live DNS was unreachable from this environment — rDNS/FCrDNS/ASN/MX checks fell back to header-only evidence and are listed under uncertainties.
                </div>
              )}
            </div>

            {/* Identity strip */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 11, marginBottom: 16 }}>
              {[["From", merged.meta.fromRaw], ["Return-Path", merged.meta.returnPath && `<${merged.meta.returnPath}>`], ["Reply-To", merged.meta.replyTo && `<${merged.meta.replyTo}>`], ["Subject", merged.meta.subject]].map(([k, v]) => (
                <div key={k} className="hf-card" style={{ border: `1px solid ${T.line}`, borderRadius: T.r2, background: T.panel, padding: "11px 13px", boxShadow: T.shadowSm }}>
                  <div style={{ fontFamily: T.mono, fontSize: 10.5, color: T.faint, letterSpacing: 0.8, fontWeight: 600 }}>{k.toUpperCase()}</div>
                  <div style={{ fontFamily: T.mono, fontSize: 12, color: v ? T.ink : T.faint, wordBreak: "break-all", marginTop: 4 }}>{v || "—"}</div>
                </div>
              ))}
            </div>

            {/* Auth chips */}
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 18 }}>
              {(() => {
                const chip = (name, r) => {
                  const c = !r ? T.faint : /pass/.test(r) ? T.good : /(fail|permerror)/.test(r) ? T.bad : T.warn;
                  return <Tag key={name} color={c}>{name}: {r || "none"}</Tag>;
                };
                return [
                  chip("SPF", merged.auth.spf?.result || merged.rspf?.result),
                  chip("DKIM", merged.auth.dkim[0]?.result || (merged.meta.dkimSigs.length ? "unverified" : null)),
                  chip("DMARC", merged.auth.dmarc?.result),
                  merged.auth.compauth && chip("compauth", merged.auth.compauth.result),
                  merged.auth.arc && chip("ARC", merged.auth.arc),
                ];
              })()}
            </div>

            <Collapsible title="Transport path — chain of custody" open right={<span style={{ fontFamily: T.mono, fontSize: 11, color: T.dim }}>{merged.hops.length} hops · origin → delivery</span>}>
              <HopRail hops={merged.hops} dns={dns} />
            </Collapsible>

            <Collapsible title="Negative indicators" open={neg.length > 0} right={<span style={{ fontFamily: T.mono, fontSize: 11.5, fontWeight: 700, color: "#0A0E1A", background: neg.length ? T.bad : T.faint, borderRadius: 999, padding: "3px 10px" }}>{neg.length}</span>}>
              {neg.length ? neg.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None identified.</div>}
            </Collapsible>
            <Collapsible title="Positive indicators" open={pos.length > 0 && !neg.length} right={<span style={{ fontFamily: T.mono, fontSize: 11.5, fontWeight: 700, color: "#0A0E1A", background: pos.length ? T.good : T.faint, borderRadius: 999, padding: "3px 10px" }}>{pos.length}</span>}>
              {pos.length ? pos.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None identified.</div>}
            </Collapsible>
            <Collapsible title="Observations, context & uncertainties" right={<span style={{ fontFamily: T.mono, fontSize: 11.5, fontWeight: 700, color: "#0A0E1A", background: T.info, borderRadius: 999, padding: "3px 10px" }}>{notes.length}</span>}>
              {notes.length ? notes.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None.</div>}
              <div style={{ marginTop: 14, fontSize: 12, color: T.dim, lineHeight: 1.65, borderTop: `1px solid ${T.line}66`, paddingTop: 12 }}>
                <strong style={{ color: T.ink }}>Standing limitations:</strong> DKIM cannot be cryptographically re-verified from headers alone (the body hash is needed), so DKIM findings rely on the receiving server's recorded verdict. Received headers below the first hop added by your own infrastructure can be forged by the sender. IP reputation is provided as manual pivot links rather than automatic queries, to keep third-party data sharing at zero by default.
              </div>
            </Collapsible>

            <Collapsible title="Recommended analyst actions" open>
              <ol style={{ margin: "8px 0 0", paddingLeft: 20 }}>
                {merged.actions.map((a, i) => (
                  <li key={i} style={{ fontSize: 13, color: T.ink, lineHeight: 1.65, marginBottom: 8 }}>{a}</li>
                ))}
              </ol>
            </Collapsible>

            <Collapsible title="Scoring ledger — how the verdict was computed">
              <div style={{ fontSize: 12.5, color: T.dim, lineHeight: 1.65, marginBottom: 12 }}>
                Every message starts at a neutral 50. Each independent finding adjusts the score by its
                evidentiary weight; no single indicator decides the verdict. Weights reflect how strongly
                each signal discriminates between legitimate and malicious mail in practice.
              </div>
              <div style={{ fontFamily: T.mono, fontSize: 12, lineHeight: 1.95, background: "#070A13", borderRadius: T.r2, padding: 14, border: `1px solid ${T.line}` }}>
                <div style={{ color: T.faint }}>baseline … 50</div>
                {merged.evidence.filter((e) => e.w !== 0).map((e, i) => (
                  <div key={i}><span style={{ color: polColor(e.pol) }}>{e.pol === "neg" ? "−" : "+"}{Math.abs(e.w)}</span> <span style={{ color: T.dim }}>{e.label}</span></div>
                ))}
                <div style={{ borderTop: `1px solid ${T.line}`, marginTop: 8, paddingTop: 8, color: T.ink, fontWeight: 700 }}>= {merged.scored.score}/100 → {merged.scored.verdict}</div>
              </div>
            </Collapsible>
          </>
        )}
      </div>
    </main>
  );
}
