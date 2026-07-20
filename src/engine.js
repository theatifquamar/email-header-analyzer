/* ============================================================
   Email Header Forensics — analysis engine (pure logic, no UI).
   Every function here runs entirely in the browser. Nothing in
   this file writes to disk, localStorage, or any network target
   other than the optional DNS-over-HTTPS calls in the DoH section,
   which send only IPs/domains, never message content.
   ============================================================ */

/* ---------------- Known infrastructure ---------------- */
export const PROVIDERS = [
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

export const FREEMAIL = /(^|@)(gmail\.com|outlook\.com|hotmail\.com|yahoo\.com|aol\.com|icloud\.com|proton\.me|protonmail\.com|mail\.ru|gmx\.(com|net|de)|qq\.com|163\.com|126\.com|yandex\.(com|ru))$/i;
export const RISKY_TLD = /\.(zip|mov|top|xyz|click|link|gq|tk|ml|cf|work|rest|country|cam|monster|quest)$/i;

/* ---------------- Parsing utilities ---------------- */
export function unfoldHeaders(raw) {
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

export function parseHeaders(raw) {
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

export const first = (h, n) => (h.map.get(n) || [])[0];
export const all = (h, n) => h.map.get(n) || [];

export const IP_RX = /\b((?:\d{1,3}\.){3}\d{1,3})\b|\[?((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\]?/gi;

export function extractIPs(s) {
  const ips = [];
  let m;
  const rx = new RegExp(IP_RX.source, "gi");
  while ((m = rx.exec(s))) {
    const ip = m[1] || m[2];
    if (ip && (m[1] ? validV4(ip) : ip.includes(":"))) ips.push(ip);
  }
  return ips;
}
export function validV4(ip) { return ip.split(".").every((o) => +o >= 0 && +o <= 255); }
export function isPrivateIP(ip) {
  if (ip.includes(":")) return /^(::1|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0;
}
export function domainOf(addr) {
  const m = String(addr || "").match(/@([A-Za-z0-9.-]+)/);
  return m ? m[1].toLowerCase().replace(/[>.\s]+$/, "") : null;
}
export function orgDomain(d) {
  if (!d) return null;
  const parts = d.toLowerCase().split(".");
  if (parts.length <= 2) return d.toLowerCase();
  const two = new Set(["co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.jp","co.nz","com.br","com.mx","co.in","com.sg","com.hk","co.za"]);
  const lastTwo = parts.slice(-2).join(".");
  return two.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}
export function matchProvider(host) {
  if (!host) return null;
  for (const p of PROVIDERS) if (p.rx.test(host)) return p;
  return null;
}

/* ---- Received: header parsing (tolerant across MTA formats) ---- */
export function parseReceived(v, idx) {
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
export function parseAuthResults(values) {
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

export function parseReceivedSPF(values) {
  const v = values[0];
  if (!v) return null;
  const m = v.match(/^(\w+)/);
  const ip = v.match(/client-ip=([^\s;]+)/i);
  const helo = v.match(/helo=([^\s;]+)/i);
  return { result: m ? m[1].toLowerCase() : null, clientIP: ip ? ip[1] : null, helo: helo ? helo[1] : null };
}

/* ---------------- DNS over HTTPS (optional, analyst-enabled) ---------------- */
export const dnsCache = new Map(); // in-memory only, cleared on page unload
export async function doh(name, type) {
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
export const revV4 = (ip) => ip.split(".").reverse().join(".");
export async function ptrLookup(ip) {
  if (ip.includes(":")) return null;
  const ans = await doh(revV4(ip) + ".in-addr.arpa", "PTR");
  return ans === null ? null : ans.map((a) => a.replace(/\.$/, ""));
}
export async function fcrdns(ip, names) {
  for (const n of names || []) {
    const a = await doh(n, "A");
    if (a === null) return null;
    if (a.some((r) => r === ip)) return { confirmed: true, name: n };
  }
  return { confirmed: false };
}
export async function asnLookup(ip) {
  if (ip.includes(":")) return null;
  const o = await doh(revV4(ip) + ".origin.asn.cymru.com", "TXT");
  if (!o || !o.length) return o === null ? null : undefined;
  const parts = o[0].split("|").map((s) => s.trim());
  const asn = parts[0].split(" ")[0];
  const detail = await doh(`AS${asn}.asn.cymru.com`, "TXT");
  const org = detail && detail.length ? detail[0].split("|").pop().trim() : null;
  return { asn, prefix: parts[1], country: parts[2], org };
}

/**
 * Domain age via RDAP (the modern WHOIS successor — JSON over HTTPS, same
 * privacy model as the DoH calls above: only the domain name is sent, never
 * message content). A domain registered days before sending "urgent" mail
 * is one of the strongest phishing signals that exists, so this is folded
 * into the weighted evidence engine, not just displayed as trivia.
 *
 * .com/.net query Verisign's RDAP server directly (no redirect — the most
 * common TLDs in business email, and CSP-friendly since there's exactly one
 * hop to one allow-listed host). Every other TLD falls back to the public
 * RDAP.org bootstrap redirector, which 302s to whichever registry is
 * authoritative; that hop may or may not be reachable under a strict CSP or
 * may 404 for TLDs that don't yet support RDAP, so failure here is treated
 * as "unavailable," never as a negative finding — same graceful-degradation
 * philosophy as the rest of the enrichment features.
 */
export async function domainAgeInfo(domain) {
  if (!domain) return null;
  const tld = domain.split(".").pop().toLowerCase();
  const urls = [];
  if (tld === "com" || tld === "net") {
    urls.push(`https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(domain)}`);
  }
  urls.push(`https://rdap.org/domain/${encodeURIComponent(domain)}`);

  for (const url of urls) {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 5000);
      const res = await fetch(url, { headers: { accept: "application/rdap+json" }, signal: ctl.signal, redirect: "follow" });
      clearTimeout(t);
      if (!res.ok) continue;
      const j = await res.json();
      const events = j.events || [];
      const reg = events.find((e) => e.eventAction === "registration");
      if (!reg?.eventDate) continue;
      const created = new Date(reg.eventDate);
      if (isNaN(created)) continue;
      const ageDays = Math.floor((Date.now() - created.getTime()) / 86400000);
      const registrarEnt = (j.entities || []).find((e) => (e.roles || []).includes("registrar"));
      const registrar = registrarEnt?.vcardArray?.[1]?.find((x) => x[0] === "fn")?.[3] || null;
      return { created, ageDays, registrar, source: url };
    } catch {
      continue; // try the next candidate, or exhaust and return null below
    }
  }
  return null; // no RDAP coverage for this TLD, or unreachable — treated as unknown, not negative
}

/* ---------------- Analysis engine ---------------- */
export function analyzeStatic(h) {
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
export const QUESTIONS = [
  { id: "expected", q: "Was this email expected by the recipient?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "pos", w: 5, label: "Message was expected", detail: "Recipient anticipated this communication." }, No: { pol: "neg", w: 5, label: "Unsolicited message", detail: "Recipient did not expect this email." } } },
  { id: "known", q: "Is the sender known or previously trusted?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "pos", w: 5, label: "Known sender relationship", detail: "Prior legitimate correspondence exists. Note: does not rule out account compromise." }, No: { pol: "neg", w: 4, label: "Unknown sender", detail: "No prior relationship with this sender." } } },
  { id: "interact", q: "Did the recipient click links or open attachments?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "note", w: 0, label: "Recipient interacted with content", detail: "Does not change the verdict, but escalates response priority: check endpoint, reset credentials if a login page was involved." } } },
  { id: "scope", q: "Was it received from an internal or external source?", opts: ["Internal", "External", "Unknown"], adj: { Internal: { pol: "note", w: 0, label: "Internal origin claimed", detail: "If headers show external origin while appearing internal, treat as high-risk spoofing." } } },
  { id: "urgency", q: "Does the content use urgency, payment, or credential pressure?", opts: ["Yes", "No", "Unknown"], adj: { Yes: { pol: "neg", w: 6, label: "Social-engineering pressure in content", detail: "Urgency + payment/credential requests is the dominant phishing lure pattern." }, No: { pol: "pos", w: 2, label: "No pressure tactics reported", detail: "Content lacks common lure characteristics." } } },
];

export function scoreEvidence(evidence) {
  let s = 50;
  for (const e of evidence) s += e.pol === "pos" ? e.w : e.pol === "neg" ? -e.w : e.w; // notes may carry small signed w
  s = Math.max(2, Math.min(98, Math.round(s)));
  const verdict = s >= 88 ? "Legitimate" : s >= 70 ? "Likely Legitimate" : s >= 45 ? "Suspicious" : s >= 22 ? "Likely Malicious" : "Malicious";
  return { score: s, verdict };
}

/* ---------------- Samples ---------------- */
export const SAMPLE_LEGIT = `Delivered-To: analyst@acme-corp.com
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

export const SAMPLE_SUS = `Delivered-To: cfo@acme-corp.com
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

