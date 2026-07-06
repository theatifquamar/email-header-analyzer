import React, { useState, useMemo, useCallback, useRef } from "react";

/* ============================================================
   HEADER FORENSICS — privacy-first email header analysis for SOC analysts
   All processing happens in browser memory. No storage APIs are used,
   nothing is logged, persisted, or transmitted except optional
   DNS-over-HTTPS lookups (hostnames/IPs only) that the analyst enables.
   ============================================================ */

/* ---------------- Design tokens ---------------- */
const T = {
  bg: "#0B1120",
  panel: "#111A2E",
  panel2: "#16223B",
  line: "#243453",
  ink: "#E7EDF7",
  dim: "#8FA0BC",
  faint: "#5E6F8D",
  accent: "#F2B84B", // signal amber — interaction color
  good: "#3DD68C",
  warn: "#F2B84B",
  bad: "#F26D6D",
  info: "#6FA8F5",
  // System stacks only: a privacy-first public deployment should not make
  // visitors' browsers call a third-party font CDN.
  mono: "ui-monospace, 'Cascadia Code', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace",
  disp: "'Segoe UI', 'Avenir Next', 'Helvetica Neue', system-ui, sans-serif",
  body: "system-ui, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif",
};

/* ---------------- Known infrastructure ---------------- */
const PROVIDERS = [
  { rx: /(^|\.)google\.com$|(^|\.)googlemail\.com$|(^|\.)gmail\.com$/i, name: "Google Workspace / Gmail", kind: "mailbox" },
  { rx: /(^|\.)outlook\.com$|(^|\.)protection\.outlook\.com$|(^|\.)office365\.com$|(^|\.)microsoft\.com$|(^|\.)hotmail\.com$/i, name: "Microsoft 365 / Exchange Online", kind: "mailbox" },
  { rx: /(^|\.)sendgrid\.net$/i, name: "Twilio SendGrid (ESP)", kind: "esp" },
  { rx: /(^|\.)mcsv\.net$|(^|\.)mcdlv\.net$|(^|\.)rsgsv\.net$|(^|\.)mailchimp\.com$|(^|\.)mandrillapp\.com$/i, name: "Mailchimp / Mandrill (ESP)", kind: "esp" },
  { rx: /(^|\.)amazonses\.com$|(^|\.)ses\.amazonaws\.com$/i, name: "Amazon SES (ESP)", kind: "esp" },
  { rx: /(^|\.)mailgun\.(net|org|info)$|(^|\.)mailgun\.com$/i, name: "Mailgun (ESP)", kind: "esp" },
  { rx: /(^|\.)postmarkapp\.com$|(^|\.)mtasv\.net$/i, name: "Postmark (ESP)", kind: "esp" },
  { rx: /(^|\.)sparkpostmail\.com$|(^|\.)sparkpost\.com$/i, name: "SparkPost (ESP)", kind: "esp" },
  { rx: /(^|\.)pphosted\.com$|(^|\.)proofpoint\.com$/i, name: "Proofpoint (secure email gateway)", kind: "seg" },
  { rx: /(^|\.)mimecast\.com$|(^|\.)mimecast-offshore\.com$/i, name: "Mimecast (secure email gateway)", kind: "seg" },
  { rx: /(^|\.)barracuda(networks)?\.com$|(^|\.)ess\.barracudanetworks\.com$/i, name: "Barracuda (secure email gateway)", kind: "seg" },
  { rx: /(^|\.)iphmx\.com$|(^|\.)ironport\.com$/i, name: "Cisco Secure Email (IronPort)", kind: "seg" },
  { rx: /(^|\.)zoho\.com$|(^|\.)zohomail\.com$/i, name: "Zoho Mail", kind: "mailbox" },
  { rx: /(^|\.)yahoo\.com$|(^|\.)yahoodns\.net$/i, name: "Yahoo Mail", kind: "mailbox" },
  { rx: /(^|\.)icloud\.com$|(^|\.)me\.com$/i, name: "Apple iCloud Mail", kind: "mailbox" },
  { rx: /(^|\.)exacttarget\.com$|(^|\.)salesforce\.com$|(^|\.)sfmc\.co$/i, name: "Salesforce Marketing Cloud (ESP)", kind: "esp" },
  { rx: /(^|\.)hubspotemail\.net$|(^|\.)hubspot\.com$/i, name: "HubSpot (ESP)", kind: "esp" },
  { rx: /(^|\.)sendinblue\.com$|(^|\.)brevo\.com$/i, name: "Brevo / Sendinblue (ESP)", kind: "esp" },
  { rx: /(^|\.)mailjet\.com$/i, name: "Mailjet (ESP)", kind: "esp" },
  { rx: /(^|\.)constantcontact\.com$|(^|\.)ctctcdn\.com$/i, name: "Constant Contact (ESP)", kind: "esp" },
  { rx: /(^|\.)qq\.com$/i, name: "Tencent QQ Mail", kind: "mailbox" },
  { rx: /(^|\.)mail\.ru$/i, name: "Mail.ru", kind: "mailbox" },
];

const FREEMAIL = /(^|@)(gmail\.com|outlook\.com|hotmail\.com|yahoo\.com|aol\.com|icloud\.com|proton\.me|protonmail\.com|mail\.ru|gmx\.(com|net|de)|qq\.com|163\.com|126\.com|yandex\.(com|ru))$/i;
const RISKY_TLD = /\.(zip|mov|top|xyz|click|link|gq|tk|ml|cf|work|rest|country|cam|monster|quest)$/i;

/* ---------------- Parsing utilities ---------------- */
function unfoldHeaders(raw) {
  // Strip a body if a full message was pasted (headers end at first blank line)
  const cut = raw.replace(/\r\n/g, "\n").split(/\n[ \t]*\n/)[0];
  const lines = cut.split("\n");
  const out = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += " " + line.trim();
    else if (line.trim()) out.push(line);
  }
  return out;
}

function parseHeaders(raw) {
  const map = new Map(); // lowercased name -> [values in original top-down order]
  const ordered = [];
  for (const line of unfoldHeaders(raw)) {
    const m = line.match(/^([!-9;-~]+):\s*(.*)$/s);
    if (!m) continue;
    const name = m[1].toLowerCase();
    if (!map.has(name)) map.set(name, []);
    map.get(name).push(m[2]);
    ordered.push({ name, value: m[2] });
  }
  return { map, ordered };
}

const first = (h, n) => (h.map.get(n) || [])[0];
const all = (h, n) => h.map.get(n) || [];

const IP_RX = /\b((?:\d{1,3}\.){3}\d{1,3})\b|\[?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\]?/gi;

function extractIPs(s) {
  const ips = [];
  let m;
  const rx = new RegExp(IP_RX.source, "gi");
  while ((m = rx.exec(s))) {
    const ip = m[1] || m[2];
    if (ip && (m[1] ? validV4(ip) : ip.includes(":"))) ips.push(ip);
  }
  return ips;
}
function validV4(ip) { return ip.split(".").every((o) => +o >= 0 && +o <= 255); }
function isPrivateIP(ip) {
  if (ip.includes(":")) return /^(::1|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0;
}
function domainOf(addr) {
  const m = String(addr || "").match(/@([A-Za-z0-9.-]+)/);
  return m ? m[1].toLowerCase().replace(/[>.\s]+$/, "") : null;
}
function orgDomain(d) {
  if (!d) return null;
  const parts = d.toLowerCase().split(".");
  if (parts.length <= 2) return d.toLowerCase();
  const two = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.jp","co.nz","com.br","com.mx","co.in","com.sg","com.hk","co.za"]);
  const lastTwo = parts.slice(-2).join(".");
  return two.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}
function matchProvider(host) {
  if (!host) return null;
  for (const p of PROVIDERS) if (p.rx.test(host)) return p;
  return null;
}

/* ---- Received: header parsing (tolerant across MTA formats) ---- */
function parseReceived(v, idx) {
  const hop = { raw: v, index: idx, fromHost: null, fromRdns: null, fromIP: null, byHost: null, with: null, id: null, tls: /\bESMTPSA?\b|\bTLS/i.test(v), date: null, ips: extractIPs(v) };
  const dm = v.match(/;\s*([^;]+)$/);
  if (dm) { const d = new Date(dm[1].trim().replace(/\(.*?\)\s*$/, "")); if (!isNaN(d)) hop.date = d; }
  const from = v.match(/\bfrom\s+([^\s()[\]]+)\s*(\(([^)]*)\))?/i);
  if (from) {
    hop.fromHost = from[1].replace(/[;,]$/, "");
    if (from[3]) {
      const inner = from[3];
      const rd = inner.match(/^\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9_-]+)+)/);
      if (rd && !validV4(rd[1])) hop.fromRdns = rd[1];
      const ips = extractIPs(inner);
      if (ips.length) hop.fromIP = ips[0];
    }
  }
  if (!hop.fromIP) {
    const bare = v.match(/\bfrom\s+\[?((?:\d{1,3}\.){3}\d{1,3})\]?/i);
    if (bare) hop.fromIP = bare[1];
  }
  const by = v.match(/\bby\s+([^\s();]+)/i);
  if (by) hop.byHost = by[1];
  const w = v.match(/\bwith\s+([A-Za-z0-9+._-]+)/i);
  if (w) hop.with = w[1];
  const id = v.match(/\bid\s+([^\s();]+)/i);
  if (id) hop.id = id[1];
  return hop;
}

/* ---- Authentication-Results parsing ---- */
function parseAuthResults(values) {
  const out = { spf: null, dkim: [], dmarc: null, compauth: null, arc: null, raw: values };
  for (const v of values) {
    const spf = v.match(/\bspf=(\w+)/i);
    if (spf && !out.spf) {
      out.spf = { result: spf[1].toLowerCase() };
      const dom = v.match(/smtp\.mailfrom=([^\s;]+)/i) || v.match(/envelope-from=["']?([^\s;"']+)/i);
      if (dom) out.spf.domain = (dom[1].includes("@") ? domainOf(dom[1]) : dom[1]).toLowerCase();
      const helo = v.match(/smtp\.helo=([^\s;]+)/i);
      if (helo) out.spf.helo = helo[1].toLowerCase();
    }
    const dkimRx = /dkim=(\w+)[^;]*?(?:header\.[di]=@?([^\s;]+))?/gi;
    let dm;
    while ((dm = dkimRx.exec(v))) out.dkim.push({ result: dm[1].toLowerCase(), domain: dm[2] ? dm[2].toLowerCase() : null });
    const dmarc = v.match(/dmarc=(\w+)[^;]*?(?:header\.from=([^\s;]+))?/i);
    if (dmarc && !out.dmarc) {
      out.dmarc = { result: dmarc[1].toLowerCase(), domain: dmarc[2] ? dmarc[2].toLowerCase() : null };
      const pol = v.match(/\bp=(\w+)/i) || v.match(/action=(\w+)/i);
      if (pol) out.dmarc.policy = pol[1].toLowerCase();
    }
    const ca = v.match(/compauth=(\w+)\s+reason=(\d+)/i);
    if (ca) out.compauth = { result: ca[1].toLowerCase(), reason: ca[2] };
    const arc = v.match(/\barc=(\w+)/i);
    if (arc) out.arc = arc[1].toLowerCase();
  }
  return out;
}

function parseReceivedSPF(values) {
  const v = values[0];
  if (!v) return null;
  const m = v.match(/^(\w+)/);
  const ip = v.match(/client-ip=([^\s;]+)/i);
  const helo = v.match(/helo=([^\s;]+)/i);
  return { result: m ? m[1].toLowerCase() : null, clientIP: ip ? ip[1] : null, helo: helo ? helo[1] : null };
}

/* ---------------- DNS over HTTPS (optional, analyst-enabled) ---------------- */
const dnsCache = new Map(); // in-memory only, cleared on page unload
async function doh(name, type) {
  const key = type + ":" + name.toLowerCase();
  if (dnsCache.has(key)) return dnsCache.get(key);
  const endpoints = [
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  ];
  for (const url of endpoints) {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 4500);
      const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: ctl.signal });
      clearTimeout(t);
      if (!res.ok) continue;
      const j = await res.json();
      const ans = (j.Answer || []).map((a) => String(a.data).replace(/^"|"$/g, ""));
      dnsCache.set(key, ans);
      return ans;
    } catch { /* try next resolver */ }
  }
  dnsCache.set(key, null); // null = lookup unavailable (offline / blocked)
  return null;
}
const revV4 = (ip) => ip.split(".").reverse().join(".");
async function ptrLookup(ip) {
  if (ip.includes(":")) return null;
  const ans = await doh(revV4(ip) + ".in-addr.arpa", "PTR");
  return ans === null ? null : ans.map((a) => a.replace(/\.$/, ""));
}
async function fcrdns(ip, names) {
  for (const n of names || []) {
    const a = await doh(n, "A");
    if (a === null) return null;
    if (a.some((r) => r === ip)) return { confirmed: true, name: n };
  }
  return { confirmed: false };
}
async function asnLookup(ip) {
  if (ip.includes(":")) return null;
  const o = await doh(revV4(ip) + ".origin.asn.cymru.com", "TXT");
  if (!o || !o.length) return o === null ? null : undefined;
  const parts = o[0].split("|").map((s) => s.trim());
  const asn = parts[0].split(" ")[0];
  const detail = await doh(`AS${asn}.asn.cymru.com`, "TXT");
  const org = detail && detail.length ? detail[0].split("|").pop().trim() : null;
  return { asn, prefix: parts[1], country: parts[2], org };
}

/* ---------------- Analysis engine ---------------- */
function analyzeStatic(h) {
  const ev = []; // {id, pol:'pos'|'neg'|'note', w, label, detail, cat}
  const add = (pol, w, label, detail, cat) => ev.push({ pol, w, label, detail, cat });

  const fromRaw = first(h, "from") || "";
  const fromDom = domainOf(fromRaw);
  const fromOrg = orgDomain(fromDom);
  const displayName = (fromRaw.match(/^\s*"?([^"<]*?)"?\s*</) || [])[1]?.trim() || null;
  const returnPath = domainOf(first(h, "return-path"));
  const replyTo = domainOf(first(h, "reply-to"));
  const messageId = first(h, "message-id");
  const dateHdr = first(h, "date");
  const subject = first(h, "subject");

  const receivedRaw = all(h, "received");
  const hops = receivedRaw.map(parseReceived).reverse(); // chronological: origin → destination
  const auth = parseAuthResults([...all(h, "authentication-results"), ...all(h, "arc-authentication-results")]);
  const rspf = parseReceivedSPF(all(h, "received-spf"));
  const dkimSigs = all(h, "dkim-signature").map((v) => ({
    d: (v.match(/\bd=([^;\s]+)/i) || [])[1]?.toLowerCase() || null,
    s: (v.match(/\bs=([^;\s]+)/i) || [])[1] || null,
  }));

  /* --- Authentication --- */
  if (auth.spf) {
    const r = auth.spf.result;
    if (r === "pass") add("pos", 12, "SPF pass", `Sending IP is authorized to send for ${auth.spf.domain || "the envelope domain"}.`, "auth");
    else if (r === "fail") add("neg", 16, "SPF fail", `Sending IP is NOT authorized for ${auth.spf.domain || "the envelope domain"} — strong spoofing signal.`, "auth");
    else if (r === "softfail") add("neg", 8, "SPF softfail", "Envelope domain marks this source as probably unauthorized (~all).", "auth");
    else if (r === "none") add("neg", 4, "No SPF record", "Envelope domain publishes no SPF policy; authenticity cannot be verified by SPF.", "auth");
    else if (r === "temperror" || r === "permerror") add("note", 0, `SPF ${r}`, "SPF could not be evaluated; treat as unverified.", "auth");
    else if (r === "neutral") add("note", 0, "SPF neutral", "Domain explicitly makes no assertion (?all).", "auth");
  } else if (rspf) {
    if (rspf.result === "pass") add("pos", 10, "SPF pass (Received-SPF)", `Client IP ${rspf.clientIP || ""} authorized by sender policy.`, "auth");
    else if (rspf.result === "fail") add("neg", 15, "SPF fail (Received-SPF)", "Client IP not authorized — strong spoofing signal.", "auth");
  } else {
    add("note", -3, "No SPF evaluation present", "Receiving server recorded no SPF verdict; authentication evidence is incomplete.", "auth");
  }

  const dkimPass = auth.dkim.find((d) => d.result === "pass");
  const dkimFail = auth.dkim.find((d) => d.result === "fail" || d.result === "permerror");
  if (dkimPass) add("pos", 12, "DKIM pass", `Message integrity verified; signed by ${dkimPass.domain || dkimSigs[0]?.d || "signing domain"}.`, "auth");
  if (dkimFail) add("neg", 12, `DKIM ${dkimFail.result}`, "Signature failed verification — content altered in transit or signature forged.", "auth");
  if (!auth.dkim.length && dkimSigs.length) add("note", 0, "DKIM signature present but unverified", `Signature by d=${dkimSigs[0].d}; the receiving server recorded no verification result. Header-only analysis cannot cryptographically verify DKIM without the message body.`, "auth");
  if (!auth.dkim.length && !dkimSigs.length) add("neg", 5, "No DKIM signature", "Message is unsigned; most legitimate bulk and corporate mail is DKIM-signed today.", "auth");

  if (auth.dmarc) {
    const r = auth.dmarc.result;
    if (r === "pass") add("pos", 14, "DMARC pass", `From: domain ${auth.dmarc.domain || fromDom || ""} is aligned and authenticated.`, "auth");
    else if (r === "fail") {
      const pol = auth.dmarc.policy ? ` Domain policy: p=${auth.dmarc.policy}.` : "";
      add("neg", 16, "DMARC fail", `From: domain failed alignment/authentication — the visible sender is not proven.${pol}`, "auth");
    } else if (r === "none") add("note", -2, "DMARC not evaluated", "No DMARC verdict recorded.", "auth");
    else if (r === "bestguesspass") add("note", 2, "DMARC best-guess pass", "No published policy; receiver inferred alignment heuristically.", "auth");
  }
  if (auth.compauth) {
    if (auth.compauth.result === "fail") add("neg", 8, "Microsoft composite auth fail", `compauth=fail reason=${auth.compauth.reason} — Exchange Online judged the sender unauthenticated.`, "auth");
    if (auth.compauth.result === "pass") add("pos", 3, "Microsoft composite auth pass", `compauth=pass reason=${auth.compauth.reason}.`, "auth");
  }

  /* --- Alignment --- */
  if (fromOrg && auth.spf?.domain) {
    const aligned = orgDomain(auth.spf.domain) === fromOrg;
    if (aligned) add("pos", 6, "SPF alignment", `Envelope sender (${auth.spf.domain}) aligns with From: domain (${fromDom}).`, "align");
    else add("note", auth.dmarc?.result === "pass" ? 0 : -5, "SPF domain not aligned with From:", `Envelope: ${auth.spf.domain} vs From: ${fromDom}. Normal for ESPs (SendGrid, Mailchimp…) using their own bounce domain, but requires DKIM alignment to pass DMARC.`, "align");
  }
  if (fromOrg && dkimPass?.domain) {
    if (orgDomain(dkimPass.domain) === fromOrg) add("pos", 6, "DKIM alignment", `DKIM d=${dkimPass.domain} aligns with From: domain.`, "align");
    else add("note", -2, "DKIM signed by third-party domain", `d=${dkimPass.domain} does not align with From: ${fromDom}. Common for ESPs without custom signing, but weakens sender proof.`, "align");
  }
  if (returnPath && fromOrg && orgDomain(returnPath) !== fromOrg && !auth.spf?.domain) {
    add("note", -3, "Return-Path differs from From:", `${returnPath} vs ${fromDom}. Legitimate for mailing lists/ESPs; also a spoofing pattern when combined with failed auth.`, "align");
  }
  if (replyTo && fromOrg && orgDomain(replyTo) !== fromOrg) {
    add("neg", FREEMAIL.test("@" + replyTo) ? 10 : 6, "Reply-To redirects to a different domain", `Replies go to ${replyTo}, not ${fromDom}. ${FREEMAIL.test("@" + replyTo) ? "Reply-To is a freemail address — classic BEC/fraud pattern." : "Verify this is intentional."}`, "content");
  }

  /* --- From heuristics --- */
  if (displayName && fromDom) {
    const brand = displayName.match(/\b(microsoft|paypal|apple|amazon|google|docusign|dhl|fedex|ups|netflix|chase|wellsfargo|bank|irs|hmrc|admin|helpdesk|it support|support team)\b/i);
    if (brand && FREEMAIL.test("@" + fromDom)) add("neg", 12, "Brand display name on freemail address", `Display name "${displayName}" with sender @${fromDom} — common impersonation pattern.`, "content");
    else if (brand && !new RegExp(brand[1].replace(/\s/g, ""), "i").test(fromDom)) add("note", -4, "Display name references a brand not in the sender domain", `"${displayName}" vs @${fromDom}. Verify the domain genuinely belongs to that brand.`, "content");
  }
  if (fromDom && RISKY_TLD.test("." + fromDom.split(".").pop())) add("neg", 6, "High-abuse TLD in sender domain", `.${fromDom.split(".").pop()} is disproportionately used in phishing campaigns.`, "content");
  if (fromDom && /xn--/.test(fromDom)) add("neg", 8, "Punycode / IDN sender domain", `${fromDom} — check for homoglyph impersonation of a known brand.`, "content");

  /* --- Message-ID --- */
  if (!messageId) add("neg", 6, "Missing Message-ID", "Nearly all legitimate MTAs add one; absence suggests a crude sending tool.", "headers");
  else {
    const midDom = (messageId.match(/@([A-Za-z0-9.-]+)/) || [])[1]?.toLowerCase();
    const known = matchProvider(midDom || "");
    if (midDom && fromOrg && orgDomain(midDom) !== fromOrg && !known) {
      add("note", -2, "Message-ID domain differs from sender", `Message-ID @${midDom} vs From: ${fromDom}. Expected for ESPs/gateways; otherwise mildly anomalous.`, "headers");
    } else if (midDom && (orgDomain(midDom) === fromOrg || known)) {
      add("pos", 2, "Message-ID consistent", known ? `Generated by ${known.name}.` : "Message-ID domain matches the sender's infrastructure.", "headers");
    }
  }

  /* --- X headers --- */
  const xmailer = first(h, "x-mailer") || first(h, "user-agent");
  if (xmailer && /\b(PHPMailer|Swift ?Mailer|Nodemailer|python|Leaf PHPMailer|xmail)\b/i.test(xmailer)) {
    add("note", -4, "Scripted mailer", `X-Mailer: ${xmailer}. Scripting libraries are used legitimately, but dominate phishing kit traffic.`, "headers");
  }
  const xorigip = extractIPs(first(h, "x-originating-ip") || "")[0];

  /* --- Received chain --- */
  if (!hops.length) {
    add("neg", 8, "No Received headers", "Cannot reconstruct the transport path; either headers were stripped or the sample is incomplete.", "path");
  } else {
    // Timestamp consistency (allow 5 min of clock skew between servers)
    let negJump = null, bigGap = null;
    for (let i = 1; i < hops.length; i++) {
      if (hops[i].date && hops[i - 1].date) {
        const d = (hops[i].date - hops[i - 1].date) / 1000;
        hops[i].delta = d;
        if (d < -300 && !negJump) negJump = { i, d };
        if (d > 3600 && !bigGap) bigGap = { i, d };
      }
    }
    if (negJump) add("neg", 8, "Timestamps run backwards in the Received chain", `Hop ${negJump.i + 1} is ${Math.abs(Math.round(negJump.d / 60))} min earlier than the previous hop — beyond normal clock skew. Possible forged Received header.`, "path");
    else if (hops.some((x, i) => i > 0 && x.date && hops[i - 1].date)) add("pos", 4, "Timestamp chain is consistent", "Hop times increase monotonically within normal clock skew.", "path");
    if (bigGap) add("note", -2, "Long delivery delay", `~${Math.round(bigGap.d / 3600)}h gap at hop ${bigGap.i + 1}. Can indicate queuing, greylisting, or staged relaying.`, "path");

    const dh = dateHdr ? new Date(dateHdr.replace(/\(.*?\)\s*$/, "")) : null;
    const lastDate = [...hops].reverse().find((x) => x.date)?.date;
    if (dh && !isNaN(dh) && lastDate) {
      const diff = (lastDate - dh) / 1000;
      if (Math.abs(diff) > 6 * 3600) add("note", -3, "Date: header far from delivery time", `Composed ${Math.round(Math.abs(diff) / 3600)}h ${diff > 0 ? "before" : "after"} final delivery. Large offsets appear in replayed or backdated mail.`, "path");
      if (diff < -600) add("neg", 5, "Date: header is in the future relative to delivery", "The claimed composition time postdates delivery — fabricated Date header.", "path");
    }

    // HELO vs rDNS-in-header comparison at origin
    const origin = hops.find((x) => x.fromIP && !isPrivateIP(x.fromIP)) || hops[0];
    if (origin) {
      origin.isOrigin = true;
      if (origin.fromHost && origin.fromRdns && orgDomain(origin.fromHost) && orgDomain(origin.fromRdns) &&
          orgDomain(origin.fromHost) !== orgDomain(origin.fromRdns) && !/^\[/.test(origin.fromHost)) {
        add("note", -4, "HELO name disagrees with reverse DNS", `HELO "${origin.fromHost}" vs rDNS "${origin.fromRdns}" at the origin hop. Misconfiguration or identity masking.`, "path");
      }
      if (origin.fromHost && /^(localhost|\[?127\.)/i.test(origin.fromHost)) add("note", -3, "Origin HELO is localhost", "Message was injected locally on the first server (webmail/script submission).", "path");
      if (rspf?.helo && origin.fromRdns && orgDomain(rspf.helo) !== orgDomain(origin.fromRdns)) {
        add("note", -2, "HELO recorded by SPF check differs from rDNS", `helo=${rspf.helo} vs ${origin.fromRdns}.`, "path");
      }
    }

    // Provider recognition along the path
    const seen = new Set();
    for (const hop of hops) {
      for (const host of [hop.fromRdns, hop.fromHost, hop.byHost]) {
        const p = matchProvider(host);
        if (p && !seen.has(p.name)) {
          seen.add(p.name);
          hop.provider = hop.provider || p;
        }
      }
    }
    if (seen.size) {
      const names = [...seen];
      const segs = names.filter((n) => /gateway/.test(n));
      add("pos", Math.min(8, 3 + seen.size * 2), "Path transits recognized infrastructure", `${names.join(" → ")}. ${segs.length ? "Security gateway hops are expected inline filtering, not suspicious forwarding." : "Routing through these services matches their documented behavior."}`, "path");
    }

    // Suspicious origin patterns
    if (origin && origin.fromIP && !isPrivateIP(origin.fromIP)) {
      if (!origin.fromRdns && !matchProvider(origin.fromHost)) {
        add("note", -4, "Origin IP has no reverse DNS recorded in headers", `${origin.fromIP} — legitimate mail servers almost always have PTR records. Confirm with live rDNS lookup.`, "path");
      }
      if (origin.fromRdns && /(\bdyn|dynamic|dsl|pool|dial|cable|ppp|res(id)?|client|host\d|ip-?\d+[-.]\d+)/i.test(origin.fromRdns) && !matchProvider(origin.fromRdns)) {
        add("neg", 8, "Origin resembles residential/dynamic IP space", `rDNS "${origin.fromRdns}" matches consumer ISP naming — typical of botnet or compromised-host sending, atypical of real mail servers.`, "path");
      }
      if (!origin.tls && hops.length > 1) add("note", -1, "Origin hop delivered without TLS", "Plaintext SMTP at the first public hop. Weak signal on its own.", "path");
    }
    if (xorigip && origin?.fromIP && xorigip !== origin.fromIP && !isPrivateIP(xorigip)) {
      add("note", 0, "X-Originating-IP differs from first hop", `${xorigip} (submitting client) vs ${origin.fromIP}. Normal for webmail; useful pivot for attribution.`, "path");
    }
    if (hops.length >= 8) add("note", -2, "Unusually long relay chain", `${hops.length} hops. Extra forwarding steps expand spoofing surface; verify each relay is expected.`, "path");
  }

  return { ev, hops, auth, rspf, meta: { fromRaw, fromDom, fromOrg, displayName, returnPath, replyTo, messageId, dateHdr, subject, dkimSigs } };
}

/* --- context question adjustments --- */
const QUESTIONS = [
  { id: "expected", q: "Was this email expected by the recipient?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "pos", w: 5, label: "Message was expected", detail: "Recipient anticipated this communication." }, No: { pol: "neg", w: 5, label: "Unsolicited message", detail: "Recipient did not expect this email." } } },
  { id: "known", q: "Is the sender known or previously trusted?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "pos", w: 5, label: "Known sender relationship", detail: "Prior legitimate correspondence exists. Note: does not rule out account compromise." }, No: { pol: "neg", w: 4, label: "Unknown sender", detail: "No prior relationship with this sender." } } },
  { id: "interact", q: "Did the recipient click links or open attachments?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "note", w: 0, label: "Recipient interacted with content", detail: "Does not change the verdict, but escalates response priority: check endpoint, reset credentials if a login page was involved." } } },
  { id: "scope", q: "Was it received from an internal or external source?", opts: ["Internal", "External", "Unknown"], adj: { Internal: { pol: "note", w: 0, label: "Internal origin claimed", detail: "If headers show external origin while appearing internal, treat as high-risk spoofing." } } },
  { id: "urgency", q: "Does the content use urgency, payment, or credential pressure?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "neg", w: 6, label: "Social-engineering pressure in content", detail: "Urgency + payment/credential requests is the dominant phishing lure pattern." }, No: { pol: "pos", w: 2, label: "No pressure tactics reported", detail: "Content lacks common lure characteristics." } } },
];

function scoreEvidence(evidence) {
  let s = 50;
  for (const e of evidence) s += e.pol === "pos" ? e.w : e.pol === "neg" ? -e.w : e.w; // notes may carry small signed w
  s = Math.max(2, Math.min(98, Math.round(s)));
  const verdict = s >= 88 ? "Legitimate" : s >= 70 ? "Likely Legitimate" : s >= 45 ? "Suspicious" : s >= 22 ? "Likely Malicious" : "Malicious";
  return { score: s, verdict };
}
const VERDICT_COLOR = { Legitimate: T.good, "Likely Legitimate": "#8FD98F", Suspicious: T.warn, "Likely Malicious": "#F2926D", Malicious: T.bad };

/* ---------------- Samples ---------------- */
const SAMPLE_LEGIT = `Delivered-To: analyst@acme-corp.com
Received: from mx2.acme-corp.com (mx2.acme-corp.com [203.0.113.25])
        by mailstore.acme-corp.com with ESMTPS id b7so221
        for <analyst@acme-corp.com>; Mon, 6 Jul 2026 09:14:22 -0700 (PDT)
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx2.acme-corp.com with ESMTPS id x12si88421
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
        Mon, 6 Jul 2026 09:14:20 -0700 (PDT)
Received-SPF: pass (acme-corp.com: domain of billing@vendorco.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41; helo=mail-sor-f41.google.com;
Authentication-Results: mx2.acme-corp.com;
       spf=pass smtp.mailfrom=billing@vendorco.com;
       dkim=pass header.i=@vendorco.com header.s=google;
       dmarc=pass (p=REJECT) header.from=vendorco.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=vendorco.com; s=google;
        h=from:to:subject:date:message-id; bh=abc123=; b=def456=
Return-Path: <billing@vendorco.com>
From: "VendorCo Billing" <billing@vendorco.com>
To: analyst@acme-corp.com
Subject: Invoice 2026-0455 for June services
Date: Mon, 6 Jul 2026 09:14:15 -0700
Message-ID: <CA+9x2Lk4@mail.gmail.com>
MIME-Version: 1.0`;

const SAMPLE_SUS = `Delivered-To: cfo@acme-corp.com
Received: from mx1.acme-corp.com (mx1.acme-corp.com [203.0.113.24])
        by mailstore.acme-corp.com with ESMTPS id q9so11
        for <cfo@acme-corp.com>; Mon, 6 Jul 2026 03:02:41 -0700 (PDT)
Received: from srv02311.example-hosting.ru (unknown [185.220.101.34])
        by mx1.acme-corp.com with ESMTP id z4si2231;
        Mon, 6 Jul 2026 03:02:39 -0700 (PDT)
Received: from [10.0.0.15] (unknown [10.0.0.15])
        by srv02311.example-hosting.ru with ESMTPA id 8f21;
        Mon, 6 Jul 2026 03:09:12 -0700 (PDT)
Received-SPF: fail (acme-corp.com: domain of microsoft.com does not designate 185.220.101.34 as permitted sender) client-ip=185.220.101.34; helo=srv02311.example-hosting.ru;
Authentication-Results: mx1.acme-corp.com;
       spf=fail smtp.mailfrom=microsoft.com;
       dkim=none;
       dmarc=fail (p=reject) header.from=microsoft.com;
       compauth=fail reason=000
Return-Path: <no-reply@microsoft.com>
From: "Microsoft 365 Admin" <no-reply@microsoft.com>
Reply-To: <acct.verify2026@gmail.com>
To: cfo@acme-corp.com
Subject: Urgent: Password expires in 2 hours - verify now
Date: Mon, 6 Jul 2026 03:01:55 -0700
X-Mailer: PHPMailer 6.8.0`;

/* ---------------- UI primitives ---------------- */
const Badge = ({ color, children }) => (
  <span style={{ display: "inline-block", padding: "2px 9px", borderRadius: 999, fontSize: 11.5, fontFamily: T.mono, fontWeight: 600, letterSpacing: 0.4, color: "#0B1120", background: color }}>{children}</span>
);
const Tag = ({ color, children }) => (
  <span style={{ display: "inline-block", padding: "1px 8px", borderRadius: 4, fontSize: 11, fontFamily: T.mono, color, border: `1px solid ${color}55`, background: color + "14" }}>{children}</span>
);

function Collapsible({ title, right, children, open: initOpen = false }) {
  const [open, setOpen] = useState(initOpen);
  return (
    <div style={{ border: `1px solid ${T.line}`, borderRadius: 10, background: T.panel, marginBottom: 12 }}>
      <button onClick={() => setOpen((o) => !o)} style={{ width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, background: "none", border: "none", color: T.ink, padding: "13px 16px", cursor: "pointer", fontFamily: T.disp, fontSize: 14.5, fontWeight: 600, textAlign: "left" }}>
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ color: T.accent, fontFamily: T.mono, fontSize: 12, transform: open ? "rotate(90deg)" : "none", transition: "transform .15s", display: "inline-block" }}>▶</span>
          {title}
        </span>
        <span>{right}</span>
      </button>
      {open && <div style={{ padding: "2px 16px 16px" }}>{children}</div>}
    </div>
  );
}

const polColor = (p) => (p === "pos" ? T.good : p === "neg" ? T.bad : T.info);
const polSym = (p) => (p === "pos" ? "＋" : p === "neg" ? "－" : "◦");

function EvidenceRow({ e }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "10px 0", borderBottom: `1px solid ${T.line}66` }}>
      <div style={{ color: polColor(e.pol), fontFamily: T.mono, fontWeight: 700, width: 18, flexShrink: 0 }}>{polSym(e.pol)}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 13.5, color: T.ink }}>{e.label}
          {e.w !== 0 && <span style={{ marginLeft: 8, fontFamily: T.mono, fontSize: 11, color: polColor(e.pol) }}>{e.pol === "neg" ? "−" : e.w > 0 ? "+" : ""}{Math.abs(e.w)}</span>}
        </div>
        <div style={{ fontSize: 12.5, color: T.dim, marginTop: 3, lineHeight: 1.5 }}>{e.detail}</div>
      </div>
    </div>
  );
}

/* ---- The signature element: chain-of-custody hop rail ---- */
function HopRail({ hops, dns }) {
  if (!hops.length) return <div style={{ color: T.dim, fontSize: 13 }}>No Received headers found — transport path cannot be reconstructed.</div>;
  return (
    <div style={{ position: "relative", paddingLeft: 4 }}>
      {hops.map((hop, i) => {
        const d = dns[hop.fromIP] || {};
        const anomalies = [];
        if (hop.delta != null && hop.delta < -300) anomalies.push("timestamp reversal");
        if (hop.fromIP && !isPrivateIP(hop.fromIP) && hop.fromRdns == null && d.ptr === undefined) anomalies.push("no rDNS in header");
        if (d.ptr === false || (Array.isArray(d.ptr) && d.ptr.length === 0)) anomalies.push("no PTR record (live)");
        if (d.fcrdns && d.fcrdns.confirmed === false) anomalies.push("FCrDNS mismatch");
        const color = anomalies.length ? T.bad : hop.provider ? T.good : T.dim;
        return (
          <div key={i} style={{ display: "flex", gap: 14, position: "relative" }}>
            {/* rail */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 26 }}>
              <div style={{ width: 12, height: 12, borderRadius: hop.isOrigin ? 2 : 999, background: color, marginTop: 6, boxShadow: `0 0 0 4px ${color}22`, flexShrink: 0 }} />
              {i < hops.length - 1 && <div style={{ width: 2, flex: 1, background: `repeating-linear-gradient(${T.line} 0 6px, transparent 6px 11px)`, minHeight: 34 }} />}
            </div>
            <div style={{ flex: 1, paddingBottom: 20, minWidth: 0 }}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "baseline" }}>
                <span style={{ fontFamily: T.mono, fontSize: 11, color: T.faint }}>HOP {i + 1}{hop.isOrigin ? " · ORIGIN" : i === hops.length - 1 ? " · DELIVERY" : ""}</span>
                {hop.date && <span style={{ fontFamily: T.mono, fontSize: 11, color: T.dim }}>{hop.date.toISOString().replace("T", " ").slice(0, 19)}Z</span>}
                {hop.delta != null && <span style={{ fontFamily: T.mono, fontSize: 11, color: hop.delta < -300 ? T.bad : hop.delta > 3600 ? T.warn : T.faint }}>Δ {hop.delta < 0 ? "−" : "+"}{Math.abs(Math.round(hop.delta))}s</span>}
                {hop.tls && <Tag color={T.good}>TLS</Tag>}
                {!hop.tls && i === 0 && <Tag color={T.faint}>no TLS</Tag>}
                {hop.provider && <Tag color={T.good}>{hop.provider.name}</Tag>}
                {anomalies.map((a) => <Tag key={a} color={T.bad}>{a}</Tag>)}
              </div>
              <div style={{ fontFamily: T.mono, fontSize: 12.5, color: T.ink, marginTop: 5, wordBreak: "break-all", lineHeight: 1.6 }}>
                <span style={{ color: T.faint }}>from </span>{hop.fromHost || "—"}
                {hop.fromRdns && hop.fromRdns !== hop.fromHost && <span style={{ color: T.dim }}> (rDNS {hop.fromRdns})</span>}
                {hop.fromIP && <span style={{ color: isPrivateIP(hop.fromIP) ? T.faint : T.accent }}> [{hop.fromIP}{isPrivateIP(hop.fromIP) ? " · private" : ""}]</span>}
                <br />
                <span style={{ color: T.faint }}>by </span>{hop.byHost || "—"}
                {hop.with && <span style={{ color: T.dim }}> with {hop.with}</span>}
              </div>
              {(d.ptr || d.asn || d.fcrdns) && (
                <div style={{ fontFamily: T.mono, fontSize: 11.5, color: T.info, marginTop: 4, lineHeight: 1.6 }}>
                  {Array.isArray(d.ptr) && d.ptr.length > 0 && <>live PTR → {d.ptr.join(", ")} {d.fcrdns?.confirmed ? "· FCrDNS ✓" : d.fcrdns ? "· FCrDNS ✗" : ""}<br /></>}
                  {d.asn && <>AS{d.asn.asn} · {d.asn.org || "unknown org"} · {d.asn.country}{d.asn.prefix ? ` · ${d.asn.prefix}` : ""}</>}
                </div>
              )}
              {hop.fromIP && !isPrivateIP(hop.fromIP) && (
                <div style={{ marginTop: 5, display: "flex", gap: 10 }}>
                  <a href={`https://www.abuseipdb.com/check/${hop.fromIP}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.faint, fontFamily: T.mono }}>AbuseIPDB ↗</a>
                  <a href={`https://www.virustotal.com/gui/ip-address/${hop.fromIP}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.faint, fontFamily: T.mono }}>VirusTotal ↗</a>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ---------------- Report builders ---------------- */
function buildMarkdown(res, answers, dns) {
  const { score, verdict } = res.scored;
  const pos = res.evidence.filter((e) => e.pol === "pos");
  const neg = res.evidence.filter((e) => e.pol === "neg");
  const notes = res.evidence.filter((e) => e.pol === "note");
  const lines = [];
  lines.push(`# Email Header Analysis Report`, ``, `**Generated:** ${new Date().toISOString()} · Header Forensics (in-memory analysis, no data retained)`, ``);
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

function recommendedActions(verdict, answers, res) {
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

function buildSummary(res, scored) {
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

/* ---------------- Main app ---------------- */
export default function App() {
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState(null);
  const [answers, setAnswers] = useState({});
  const [dns, setDns] = useState({});
  const [dnsLive, setDnsLive] = useState(null); // null unknown, true worked, false blocked
  const [useDns, setUseDns] = useState(true);
  const [busy, setBusy] = useState(false);
  const reportRef = useRef(null);

  const analyze = useCallback(async () => {
    if (!raw.trim()) return;
    setBusy(true);
    setAnswers({});
    const h = parseHeaders(raw);
    const base = analyzeStatic(h);
    const res = { ...base, evidence: base.ev, dnsLive: false };
    setDns({});
    setResult({ ...res, scored: scoreEvidence(res.evidence), summary: "", actions: [] });

    // Optional live DNS enrichment (IPs/domains only — never message content)
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
      // Domain checks for the From: domain
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
      }
    }

    // Fold DNS findings into evidence
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

  // Merge analyst answers → recompute
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

  const needQuestions = merged && (merged.scored.score >= 30 && merged.scored.score <= 80 || !merged.auth.spf && !merged.rspf);
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

  const pos = merged?.evidence.filter((e) => e.pol === "pos") || [];
  const neg = merged?.evidence.filter((e) => e.pol === "neg") || [];
  const notes = merged?.evidence.filter((e) => e.pol === "note") || [];

  return (
    <div style={{ minHeight: "100vh", background: T.bg, color: T.ink, fontFamily: T.body }}>
      <style>{`
        * { box-sizing: border-box; }
        textarea:focus, button:focus-visible, a:focus-visible { outline: 2px solid ${T.accent}; outline-offset: 2px; }
        a { color: ${T.info}; text-decoration: none; }
        ::selection { background: ${T.accent}44; }
        @media print {
          body { background: #fff !important; }
          .no-print { display: none !important; }
          .print-area { color: #111 !important; }
        }
        @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
      `}</style>

      {/* Top bar */}
      <header className="no-print" style={{ borderBottom: `1px solid ${T.line}`, padding: "14px 22px", display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
        <div style={{ fontFamily: T.disp, fontWeight: 700, fontSize: 17, letterSpacing: 0.3 }}>
          <span style={{ color: T.accent }}>▮</span> HEADER FORENSICS
        </div>
        <div style={{ fontFamily: T.mono, fontSize: 11, color: T.dim }}>email transport & authentication triage</div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8, fontFamily: T.mono, fontSize: 11, color: T.good }}>
          <span style={{ width: 7, height: 7, borderRadius: 99, background: T.good, display: "inline-block" }} />
          IN-MEMORY ONLY · NOTHING STORED, LOGGED, OR SENT
        </div>
      </header>

      <main style={{ maxWidth: 1240, margin: "0 auto", padding: "22px 22px 60px", display: "grid", gridTemplateColumns: "minmax(300px, 400px) 1fr", gap: 22, alignItems: "start" }}>
        {/* ===== Left: input & context ===== */}
        <div className="no-print" style={{ display: "flex", flexDirection: "column", gap: 14, position: "sticky", top: 16 }}>
          <div style={{ border: `1px solid ${T.line}`, borderRadius: 10, background: T.panel, padding: 16 }}>
            <div style={{ fontFamily: T.disp, fontWeight: 600, fontSize: 14, marginBottom: 4 }}>Paste raw headers</div>
            <div style={{ fontSize: 12, color: T.dim, marginBottom: 10, lineHeight: 1.5 }}>
              Full message source is fine — the body is discarded at the first blank line. Everything is analyzed in this tab's memory and vanishes when you leave.
            </div>
            <textarea
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              spellCheck={false}
              placeholder={"Received: from ...\nAuthentication-Results: ...\nFrom: ..."}
              style={{ width: "100%", height: 220, background: "#0A0F1C", color: T.ink, border: `1px solid ${T.line}`, borderRadius: 8, padding: 12, fontFamily: T.mono, fontSize: 12, lineHeight: 1.55, resize: "vertical" }}
            />
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", margin: "10px 0", fontSize: 12, color: T.dim, cursor: "pointer" }}>
              <input type="checkbox" checked={useDns} onChange={(e) => setUseDns(e.target.checked)} style={{ marginTop: 2, accentColor: T.accent }} />
              <span>Live DNS enrichment (PTR, FCrDNS, ASN, MX, SPF, DMARC) via DNS-over-HTTPS. Sends only IPs and domain names to the resolver — never message content. Uncheck for fully offline analysis.</span>
            </label>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={analyze} disabled={busy || !raw.trim()} style={{ background: T.accent, color: "#0B1120", border: "none", borderRadius: 8, padding: "10px 18px", fontFamily: T.disp, fontWeight: 700, fontSize: 13.5, cursor: raw.trim() ? "pointer" : "not-allowed", opacity: raw.trim() ? 1 : 0.5 }}>
                {busy ? "Analyzing…" : "Analyze headers"}
              </button>
              <button onClick={() => { setRaw(""); setResult(null); setAnswers({}); setDns({}); dnsCache.clear(); }} style={{ background: "none", color: T.dim, border: `1px solid ${T.line}`, borderRadius: 8, padding: "10px 14px", fontSize: 12.5, cursor: "pointer" }}>
                Clear everything
              </button>
            </div>
            <div style={{ display: "flex", gap: 12, marginTop: 10 }}>
              <button onClick={() => setRaw(SAMPLE_LEGIT)} style={{ background: "none", border: "none", color: T.info, fontSize: 11.5, fontFamily: T.mono, cursor: "pointer", padding: 0 }}>load legit sample</button>
              <button onClick={() => setRaw(SAMPLE_SUS)} style={{ background: "none", border: "none", color: T.info, fontSize: 11.5, fontFamily: T.mono, cursor: "pointer", padding: 0 }}>load phishing sample</button>
            </div>
          </div>

          {/* Context questions */}
          {merged && needQuestions && (
            <div style={{ border: `1px solid ${T.accent}44`, borderRadius: 10, background: T.panel, padding: 16 }}>
              <div style={{ fontFamily: T.disp, fontWeight: 600, fontSize: 14, color: T.accent }}>Header evidence isn't conclusive</div>
              <div style={{ fontSize: 12, color: T.dim, margin: "4px 0 12px", lineHeight: 1.5 }}>
                These answers materially change the assessment. Answers stay in memory with everything else.
              </div>
              {QUESTIONS.map((q) => (
                <div key={q.id} style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 12.5, marginBottom: 6 }}>{q.q}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {q.opts.map((o) => (
                      <button key={o} onClick={() => setAnswers((a) => ({ ...a, [q.id]: a[q.id] === o ? null : o }))}
                        style={{ padding: "5px 12px", borderRadius: 999, fontSize: 12, fontFamily: T.mono, cursor: "pointer", border: `1px solid ${answers[q.id] === o ? T.accent : T.line}`, background: answers[q.id] === o ? T.accent : "transparent", color: answers[q.id] === o ? "#0B1120" : T.dim, fontWeight: answers[q.id] === o ? 700 : 400 }}>
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
            <div style={{ border: `1px solid ${T.line}`, borderRadius: 10, background: T.panel, padding: 14, fontSize: 12, color: T.dim, lineHeight: 1.5 }}>
              Header evidence is strong enough that recipient context wouldn't change the verdict band, so no follow-up questions are needed. You can still document context in your ticket.
            </div>
          )}
        </div>

        {/* ===== Right: results ===== */}
        <div className="print-area" ref={reportRef}>
          {!merged && (
            <div style={{ border: `1px dashed ${T.line}`, borderRadius: 12, padding: "60px 30px", textAlign: "center", color: T.faint }}>
              <div style={{ fontFamily: T.disp, fontSize: 20, fontWeight: 600, color: T.dim, marginBottom: 8 }}>Awaiting evidence</div>
              <div style={{ fontSize: 13, maxWidth: 460, margin: "0 auto", lineHeight: 1.6 }}>
                Paste headers on the left. The analyzer reconstructs the transport chain, validates SPF/DKIM/DMARC and alignment, checks timestamps, recognizes legitimate ESP and gateway infrastructure, and correlates everything into an evidence-weighted verdict.
              </div>
            </div>
          )}

          {merged && (
            <>
              {/* Verdict panel */}
              <div style={{ border: `1px solid ${VERDICT_COLOR[merged.scored.verdict]}55`, borderRadius: 12, background: `linear-gradient(180deg, ${VERDICT_COLOR[merged.scored.verdict]}14, ${T.panel})`, padding: "20px 22px", marginBottom: 14 }}>
                <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center" }}>
                  <div>
                    <div style={{ fontFamily: T.mono, fontSize: 11, color: T.dim, letterSpacing: 1 }}>VERDICT</div>
                    <div style={{ fontFamily: T.disp, fontSize: 30, fontWeight: 700, color: VERDICT_COLOR[merged.scored.verdict], lineHeight: 1.15 }}>{merged.scored.verdict}</div>
                  </div>
                  <div style={{ flex: 1, minWidth: 220 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontFamily: T.mono, fontSize: 11, color: T.dim, marginBottom: 5 }}>
                      <span>confidence in legitimacy</span><span style={{ color: T.ink, fontWeight: 600 }}>{merged.scored.score}/100</span>
                    </div>
                    <div style={{ height: 8, borderRadius: 99, background: "#0A0F1C", overflow: "hidden", border: `1px solid ${T.line}` }}>
                      <div style={{ width: `${merged.scored.score}%`, height: "100%", background: VERDICT_COLOR[merged.scored.verdict], transition: "width .3s" }} />
                    </div>
                    <div style={{ fontSize: 11, color: T.faint, marginTop: 6, fontFamily: T.mono }}>
                      capped at 2–98: header evidence alone never supports absolute certainty
                    </div>
                  </div>
                  <div className="no-print" style={{ display: "flex", gap: 8 }}>
                    <button onClick={exportMd} style={{ background: "none", color: T.ink, border: `1px solid ${T.line}`, borderRadius: 8, padding: "9px 14px", fontSize: 12.5, cursor: "pointer", fontFamily: T.mono }}>↓ Markdown</button>
                    <button onClick={() => window.print()} style={{ background: "none", color: T.ink, border: `1px solid ${T.line}`, borderRadius: 8, padding: "9px 14px", fontSize: 12.5, cursor: "pointer", fontFamily: T.mono }}>↓ PDF</button>
                  </div>
                </div>
                <p style={{ fontSize: 13.5, color: T.ink, lineHeight: 1.65, margin: "14px 0 0" }}>{merged.summary}</p>
                {dnsLive === false && useDns && (
                  <div style={{ marginTop: 10, fontSize: 11.5, fontFamily: T.mono, color: T.warn }}>
                    ⚠ Live DNS was unreachable from this environment — rDNS/FCrDNS/ASN/MX checks fell back to header-only evidence and are listed under uncertainties.
                  </div>
                )}
              </div>

              {/* Identity strip */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10, marginBottom: 14 }}>
                {[["From", merged.meta.fromRaw], ["Return-Path", merged.meta.returnPath && `<${merged.meta.returnPath}>`], ["Reply-To", merged.meta.replyTo && `<${merged.meta.replyTo}>`], ["Subject", merged.meta.subject]].map(([k, v]) => (
                  <div key={k} style={{ border: `1px solid ${T.line}`, borderRadius: 8, background: T.panel, padding: "10px 12px" }}>
                    <div style={{ fontFamily: T.mono, fontSize: 10.5, color: T.faint, letterSpacing: 0.8 }}>{k.toUpperCase()}</div>
                    <div style={{ fontFamily: T.mono, fontSize: 12, color: v ? T.ink : T.faint, wordBreak: "break-all", marginTop: 3 }}>{v || "—"}</div>
                  </div>
                ))}
              </div>

              {/* Auth chips */}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
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

              {/* Hop rail */}
              <Collapsible title="Transport path — chain of custody" open right={<span style={{ fontFamily: T.mono, fontSize: 11, color: T.dim }}>{merged.hops.length} hops · origin → delivery</span>}>
                <HopRail hops={merged.hops} dns={dns} />
              </Collapsible>

              {/* Evidence */}
              <Collapsible title="Negative indicators" open={neg.length > 0} right={<Badge color={neg.length ? T.bad : T.faint}>{neg.length}</Badge>}>
                {neg.length ? neg.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None identified.</div>}
              </Collapsible>
              <Collapsible title="Positive indicators" open={pos.length > 0 && !neg.length} right={<Badge color={pos.length ? T.good : T.faint}>{pos.length}</Badge>}>
                {pos.length ? pos.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None identified.</div>}
              </Collapsible>
              <Collapsible title="Observations, context & uncertainties" right={<Badge color={T.info}>{notes.length}</Badge>}>
                {notes.length ? notes.map((e, i) => <EvidenceRow key={i} e={e} />) : <div style={{ color: T.dim, fontSize: 13 }}>None.</div>}
                <div style={{ marginTop: 12, fontSize: 12, color: T.dim, lineHeight: 1.6, borderTop: `1px solid ${T.line}66`, paddingTop: 10 }}>
                  <strong style={{ color: T.ink }}>Standing limitations:</strong> DKIM cannot be cryptographically re-verified from headers alone (the body hash is needed), so DKIM findings rely on the receiving server's recorded verdict. Received headers below the first hop added by your own infrastructure can be forged by the sender. IP reputation is provided as manual pivot links rather than automatic queries, to keep third-party data sharing at zero by default.
                </div>
              </Collapsible>

              {/* Actions */}
              <Collapsible title="Recommended analyst actions" open>
                <ol style={{ margin: "6px 0 0", paddingLeft: 20 }}>
                  {merged.actions.map((a, i) => (
                    <li key={i} style={{ fontSize: 13, color: T.ink, lineHeight: 1.6, marginBottom: 7 }}>{a}</li>
                  ))}
                </ol>
              </Collapsible>

              {/* Raw evidence ledger */}
              <Collapsible title="Scoring ledger — how the verdict was computed">
                <div style={{ fontSize: 12.5, color: T.dim, lineHeight: 1.6, marginBottom: 10 }}>
                  Every message starts at a neutral 50. Each independent finding adjusts the score by its evidentiary weight; no single indicator decides the verdict. Weights reflect how strongly each signal discriminates between legitimate and malicious mail in practice (e.g., a DMARC fail against an enforcing policy outweighs a missing Message-ID).
                </div>
                <div style={{ fontFamily: T.mono, fontSize: 12, lineHeight: 1.9 }}>
                  <div style={{ color: T.faint }}>baseline … 50</div>
                  {merged.evidence.filter((e) => e.w !== 0).map((e, i) => (
                    <div key={i}><span style={{ color: polColor(e.pol) }}>{e.pol === "neg" ? "−" : "+"}{Math.abs(e.w)}</span> <span style={{ color: T.dim }}>{e.label}</span></div>
                  ))}
                  <div style={{ borderTop: `1px solid ${T.line}`, marginTop: 6, paddingTop: 6, color: T.ink }}>= {merged.scored.score}/100 → {merged.scored.verdict}</div>
                </div>
              </Collapsible>
            </>
          )}
        </div>
      </main>

      <footer className="no-print" style={{ borderTop: `1px solid ${T.line}`, padding: "14px 22px", fontSize: 11.5, fontFamily: T.mono, color: T.faint, lineHeight: 1.7, maxWidth: 1240, margin: "0 auto" }}>
        PRIVACY: analysis runs entirely in this tab's memory. No storage APIs are used; nothing is logged, persisted, indexed, trained on, or shared. Optional DNS-over-HTTPS enrichment transmits only IP addresses and domain names to the public resolver you can disable above. Closing or reloading the page destroys all data, including the in-memory DNS cache.
      </footer>
    </div>
  );
}
