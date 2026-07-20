import { describe, it, expect } from "vitest";
import {
  parseHeaders, analyzeStatic, scoreEvidence, unfoldHeaders, extractIPs,
  validV4, isPrivateIP, domainOf, orgDomain, matchProvider, parseReceived,
  parseAuthResults, QUESTIONS, SAMPLE_LEGIT, SAMPLE_SUS,
} from "../engine.js";

/* ============================================================
   Regression suite: known-good and known-bad header samples.
   These are the same two samples shown in the analyzer's UI
   ("load legit sample" / "load phishing sample"), used here as
   the project's ground truth for scoring regression protection.
   If a future change to the evidence engine flips either verdict,
   these tests fail — that's the point.
   ============================================================ */

describe("regression: known-legitimate sample", () => {
  const h = parseHeaders(SAMPLE_LEGIT);
  const result = analyzeStatic(h);
  const scored = scoreEvidence(result.ev);

  it("parses the From/Return-Path/Subject correctly", () => {
    expect(result.meta.fromDom).toBe("vendorco.com");
    expect(result.meta.returnPath).toBe("vendorco.com");
    expect(result.meta.subject).toMatch(/Invoice/);
  });

  it("recognizes SPF/DKIM/DMARC all passing", () => {
    expect(result.auth.spf.result).toBe("pass");
    expect(result.auth.dkim[0]?.result).toBe("pass");
    expect(result.auth.dmarc.result).toBe("pass");
  });

  it("reconstructs a 2-hop chronological chain", () => {
    expect(result.hops.length).toBe(2);
  });

  it("scores in the Legitimate or Likely Legitimate band", () => {
    expect(scored.score).toBeGreaterThanOrEqual(70);
    expect(["Legitimate", "Likely Legitimate"]).toContain(scored.verdict);
  });

  it("never claims absolute certainty (hard cap below 100)", () => {
    expect(scored.score).toBeLessThanOrEqual(98);
  });
});

describe("regression: known-phishing sample", () => {
  const h = parseHeaders(SAMPLE_SUS);
  const result = analyzeStatic(h);
  const scored = scoreEvidence(result.ev);

  it("recognizes SPF/DMARC failing against microsoft.com", () => {
    expect(result.auth.spf.result).toBe("fail");
    expect(result.auth.dmarc.result).toBe("fail");
  });

  it("flags the Reply-To redirect to a freemail domain", () => {
    expect(result.meta.replyTo).toBe("gmail.com");
    const found = result.ev.some((e) => /Reply-To/i.test(e.label));
    expect(found).toBe(true);
  });

  it("detects the backwards timestamp in the Received chain", () => {
    const found = result.ev.some((e) => /timestamp/i.test(e.label) && e.pol === "neg");
    expect(found).toBe(true);
  });

  it("scores in the Malicious or Likely Malicious band", () => {
    expect(scored.score).toBeLessThanOrEqual(44);
    expect(["Malicious", "Likely Malicious"]).toContain(scored.verdict);
  });

  it("never claims absolute certainty (hard cap above 0)", () => {
    expect(scored.score).toBeGreaterThanOrEqual(2);
  });
});

/* ============================================================
   Unit tests for individual parsing primitives
   ============================================================ */

describe("unfoldHeaders", () => {
  it("joins folded continuation lines back into one logical line", () => {
    const raw = "Received: from a.example.com\n  (using TLSv1.2)\n  by b.example.com;\nFrom: test@example.com";
    const lines = unfoldHeaders(raw);
    expect(lines.length).toBe(2);
    expect(lines[0]).toMatch(/a\.example\.com.*using TLSv1\.2.*b\.example\.com/s);
  });

  it("discards everything after the first blank line (the message body)", () => {
    const raw = "From: a@b.com\nSubject: hi\n\nThis is the body\nwith a fake header: injected";
    const lines = unfoldHeaders(raw);
    expect(lines.some((l) => /fake header/.test(l))).toBe(false);
  });
});

describe("extractIPs / validV4 / isPrivateIP", () => {
  it("extracts a valid IPv4 address from arbitrary text", () => {
    expect(extractIPs("from mx1 [203.0.113.5] by mx2")).toContain("203.0.113.5");
  });

  it("rejects octets over 255 as a valid IPv4", () => {
    expect(validV4("999.1.1.1")).toBe(false);
    expect(validV4("192.168.1.1")).toBe(true);
  });

  it("classifies RFC1918 and loopback ranges as private", () => {
    expect(isPrivateIP("10.0.0.5")).toBe(true);
    expect(isPrivateIP("192.168.1.1")).toBe(true);
    expect(isPrivateIP("127.0.0.1")).toBe(true);
    expect(isPrivateIP("8.8.8.8")).toBe(false);
  });
});

describe("domainOf / orgDomain", () => {
  it("extracts the domain from an email address", () => {
    expect(domainOf("Someone <user@Example.COM>")).toBe("example.com");
  });

  it("collapses a subdomain to its organizational (registrable) domain", () => {
    expect(orgDomain("mail.marketing.example.com")).toBe("example.com");
  });

  it("handles known second-level ccTLD suffixes (e.g. co.uk)", () => {
    expect(orgDomain("mail.example.co.uk")).toBe("example.co.uk");
  });
});

describe("matchProvider", () => {
  it("recognizes a known ESP hostname", () => {
    expect(matchProvider("mail-sor-f41.google.com")?.name).toMatch(/Google/);
    expect(matchProvider("something.sendgrid.net")?.name).toMatch(/SendGrid/);
  });

  it("returns null for an unrecognized hostname", () => {
    expect(matchProvider("srv02311.example-hosting.ru")).toBeNull();
  });
});

describe("parseReceived", () => {
  it("extracts from/by/with/ip/timestamp from a realistic Received header", () => {
    const v = "from mail.example.com (mail.example.com [203.0.113.9]) by mx.acme.com with ESMTPS id abc123; Mon, 6 Jul 2026 09:14:20 -0700 (PDT)";
    const hop = parseReceived(v, 0);
    expect(hop.fromHost).toBe("mail.example.com");
    expect(hop.fromIP).toBe("203.0.113.9");
    expect(hop.byHost).toBe("mx.acme.com");
    expect(hop.with).toBe("ESMTPS");
    expect(hop.date).toBeInstanceOf(Date);
  });
});

describe("parseAuthResults", () => {
  it("parses SPF, DKIM, and DMARC verdicts from a combined header", () => {
    const v = ["mx.acme.com; spf=pass smtp.mailfrom=vendor.com; dkim=pass header.i=@vendor.com header.s=sel1; dmarc=pass (p=REJECT) header.from=vendor.com"];
    const auth = parseAuthResults(v);
    expect(auth.spf.result).toBe("pass");
    expect(auth.spf.domain).toBe("vendor.com");
    expect(auth.dkim[0].result).toBe("pass");
    expect(auth.dmarc.result).toBe("pass");
    expect(auth.dmarc.policy).toBe("reject");
  });
});

/* ============================================================
   Scoring engine invariants
   ============================================================ */

describe("scoreEvidence", () => {
  it("returns exactly the neutral baseline (50) with no evidence", () => {
    expect(scoreEvidence([]).score).toBe(50);
  });

  it("never returns a score outside the documented 2–98 hard cap", () => {
    const allNeg = Array.from({ length: 20 }, () => ({ pol: "neg", w: 20 }));
    const allPos = Array.from({ length: 20 }, () => ({ pol: "pos", w: 20 }));
    expect(scoreEvidence(allNeg).score).toBeGreaterThanOrEqual(2);
    expect(scoreEvidence(allPos).score).toBeLessThanOrEqual(98);
  });

  it("maps score ranges to the correct verdict band", () => {
    expect(scoreEvidence([{ pol: "pos", w: 40 }]).verdict).toBe("Legitimate");
    expect(scoreEvidence([{ pol: "neg", w: 40 }]).verdict).toBe("Malicious");
    expect(scoreEvidence([]).verdict).toBe("Suspicious");
  });
});

describe("QUESTIONS", () => {
  it("every question has at least two mutually distinct options", () => {
    for (const q of QUESTIONS) {
      expect(q.opts.length).toBeGreaterThanOrEqual(2);
      expect(new Set(q.opts).size).toBe(q.opts.length);
    }
  });
});
