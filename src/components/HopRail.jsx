import React from "react";
import { T } from "../theme.js";
import { isPrivateIP } from "../engine.js";
import { Tag } from "./Primitives.jsx";

export function HopRail({ hops, dns }) {
  if (!hops.length) {
    return (
      <div style={{ color: T.dim, fontSize: 13 }}>
        No Received headers found — transport path cannot be reconstructed.
      </div>
    );
  }
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
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 26 }}>
              <div
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: hop.isOrigin ? 3 : 999,
                  background: color,
                  marginTop: 6,
                  boxShadow: `0 0 0 4px ${color}22`,
                  flexShrink: 0,
                }}
              />
              {i < hops.length - 1 && (
                <div
                  style={{
                    width: 2,
                    flex: 1,
                    background: `repeating-linear-gradient(${T.line} 0 6px, transparent 6px 11px)`,
                    minHeight: 34,
                  }}
                />
              )}
            </div>
            <div style={{ flex: 1, paddingBottom: 22, minWidth: 0 }}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "baseline" }}>
                <span style={{ fontFamily: T.mono, fontSize: 11, color: T.faint, fontWeight: 600 }}>
                  HOP {i + 1}
                  {hop.isOrigin ? " · ORIGIN" : i === hops.length - 1 ? " · DELIVERY" : ""}
                </span>
                {hop.date && (
                  <span style={{ fontFamily: T.mono, fontSize: 11, color: T.dim }}>
                    {hop.date.toISOString().replace("T", " ").slice(0, 19)}Z
                  </span>
                )}
                {hop.delta != null && (
                  <span
                    style={{
                      fontFamily: T.mono,
                      fontSize: 11,
                      color: hop.delta < -300 ? T.bad : hop.delta > 3600 ? T.warn : T.faint,
                    }}
                  >
                    Δ {hop.delta < 0 ? "−" : "+"}
                    {Math.abs(Math.round(hop.delta))}s
                  </span>
                )}
                {hop.tls && <Tag color={T.good}>TLS</Tag>}
                {!hop.tls && i === 0 && <Tag color={T.faint}>no TLS</Tag>}
                {hop.provider && <Tag color={T.good}>{hop.provider.name}</Tag>}
                {anomalies.map((a) => (
                  <Tag key={a} color={T.bad}>
                    {a}
                  </Tag>
                ))}
              </div>
              <div style={{ fontFamily: T.mono, fontSize: 12.5, color: T.ink, marginTop: 6, wordBreak: "break-all", lineHeight: 1.6 }}>
                <span style={{ color: T.faint }}>from </span>
                {hop.fromHost || "—"}
                {hop.fromRdns && hop.fromRdns !== hop.fromHost && <span style={{ color: T.dim }}> (rDNS {hop.fromRdns})</span>}
                {hop.fromIP && (
                  <span style={{ color: isPrivateIP(hop.fromIP) ? T.faint : T.accent }}>
                    {" "}
                    [{hop.fromIP}
                    {isPrivateIP(hop.fromIP) ? " · private" : ""}]
                  </span>
                )}
                <br />
                <span style={{ color: T.faint }}>by </span>
                {hop.byHost || "—"}
                {hop.with && <span style={{ color: T.dim }}> with {hop.with}</span>}
              </div>
              {(d.ptr || d.asn || d.fcrdns) && (
                <div style={{ fontFamily: T.mono, fontSize: 11.5, color: T.info, marginTop: 5, lineHeight: 1.6 }}>
                  {Array.isArray(d.ptr) && d.ptr.length > 0 && (
                    <>
                      live PTR → {d.ptr.join(", ")} {d.fcrdns?.confirmed ? "· FCrDNS ✓" : d.fcrdns ? "· FCrDNS ✗" : ""}
                      <br />
                    </>
                  )}
                  {d.asn && (
                    <>
                      AS{d.asn.asn} · {d.asn.org || "unknown org"} · {d.asn.country}
                      {d.asn.prefix ? ` · ${d.asn.prefix}` : ""}
                    </>
                  )}
                </div>
              )}
              {hop.fromIP && !isPrivateIP(hop.fromIP) && (
                <div className="no-print" style={{ marginTop: 6, display: "flex", gap: 12 }}>
                  <a href={`https://www.abuseipdb.com/check/${hop.fromIP}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.faint, fontFamily: T.mono }}>
                    AbuseIPDB ↗
                  </a>
                  <a href={`https://www.virustotal.com/gui/ip-address/${hop.fromIP}`} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.faint, fontFamily: T.mono }}>
                    VirusTotal ↗
                  </a>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
