// src/server.ts

import dotenv from "dotenv";
dotenv.config();

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import net from "net";
import { randomUUID } from "crypto"; // ← TAMBAH
import type { Server } from "http";
/* ===============================
   SERVICES
============================== */
import { fetchVirusTotal } from "./services/virustotal.js";
import { getAbuseIPDB, getLocationFallback } from "./services/abuseipdb.js";
import { generateReportAI } from "./services/qwen3.js";
import { searchMISP } from "./services/misp.js";
import {
  calculateConfidence,
  analyzeThreatToMitigation,
} from "./services/mitigation.js";
import {
  matchCVE,
  calculateCVERiskScore,
  type CVEMatchResult,
  type CVERiskScore,
} from "./services/cve.js";
import { fetchWHOIS } from "./services/whois.js";
/* ===============================
   CORE
============================== */
import { generateCorrelationInsights } from "./core/correlation.js";
/* ── History & WS ── */ // ← TAMBAH BLOK INI
import {
  saveToHistory,
  loadHistory,
  getReportById,
} from "./services/historyStore.js";
import { initWSS, broadcastNewReport } from "./services/wsManager.js";
/* ===============================
   ROUTES
============================== */
import exportRoute from "./routes/export.js";
import nvdRoute from "./routes/nvd.js";

/* ===============================
   APP
============================== */
const app = new Hono();

app.use("*", cors());

/* ===============================
   SUB ROUTES
============================== */
app.route("/api", exportRoute);
app.route("/api/nvd", nvdRoute);

/* ===============================
   ROOT
============================== */
app.get("/", (c) => c.text("Threat Intelligence API running"));

/* ══════════════════════════════════════
   GET /history  — ambil semua history
══════════════════════════════════════ */
app.get("/history", (c) => {
  try {
    const history = loadHistory();
    return c.json({ success: true, history });
  } catch (err) {
    console.error("[history]", err);
    return c.json({ error: "Failed to load history" }, 500);
  }
});

/* ══════════════════════════════════════
   GET /history/:id  — ambil satu report
══════════════════════════════════════ */
app.get("/history/:id", (c) => {
  const reportId = c.req.param("id");
  const entry = getReportById(reportId);
  if (!entry) return c.json({ error: "Report not found" }, 404);
  return c.json({ success: true, entry });
});

/* ===============================
   MISP ONLY
============================== */
app.post("/misp/search", async (c) => {
  try {
    const { indicator } = await c.req.json();

    if (!indicator) {
      return c.json({ error: "indicator required" }, 400);
    }

    const mispData = await searchMISP(indicator);

    return c.json({
      success: true,
      mispData,
    });
  } catch (err) {
    console.error(err);

    return c.json(
      {
        error: "Failed fetch MISP data",
      },
      500,
    );
  }
});

/* ===============================
   MAIN ANALYZE
============================== */
app.post("/chat", async (c) => {
  try {
    const {
      indicator,
      type,
      username = "Unknown",
      email = "unknown@-",
    } = await c.req.json();

    if (!indicator || !type) {
      return c.json({ error: "indicator & type required" }, 400);
    }

    /* ── Generate reportId unik ── */ // ← TAMBAH
    const now = new Date();
    const datePart = now.toISOString().slice(0, 10).replace(/-/g, "");
    const randPart = randomUUID().slice(0, 4).toUpperCase();
    const reportId = `RPT-${datePart}-${randPart}`;

    /* ===============================
       VIRUSTOTAL
    ============================== */
    const vt = await fetchVirusTotal(indicator, type);
    // ── WHOIS (hanya untuk IP) ──
    let whoisData = null;
    if (type === "ip") {
      whoisData = await fetchWHOIS(indicator);
    }

    /* ===============================
       ABUSEIPDB
    ============================== */
    let abuseipdb = null;

    if (type === "ip") {
      abuseipdb = await getAbuseIPDB(indicator);
    }

    /* ===============================
       MISP
    ============================== */
    const mispData = await searchMISP(indicator);

    /* ===============================
       VT STATS
    ============================== */
    const stats = vt.stats || {};

    const malicious = stats.malicious || 0;

    const suspicious = stats.suspicious || 0;

    const harmless = stats.harmless || 0;

    const undetected = stats.undetected || 0;

    const totalVendors = malicious + suspicious + harmless + undetected;

    const abuseScore = abuseipdb?.abuse_confidence_score || 0;

    const totalReports = abuseipdb?.total_reports || 0;

    let nvdData = null;
    /* ──────────────────────────────
       5. CVE MATCHING (BARU)
       Jalankan parallel dengan pipeline lain
    ────────────────────────────── */
    let cveMatches: CVEMatchResult[] = [];
    let cveRiskScore: CVERiskScore = {
      score: 0,
      highest_cvss: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      exploit_count: 0,
    };

    try {
      cveMatches = await matchCVE({ vtResult: vt, abuseipdb, mispData });
      cveRiskScore = calculateCVERiskScore(cveMatches);
      console.log(`[CVE] ${cveMatches.length} CVE(s) matched for ${indicator}`);
    } catch (cveErr) {
      // CVE matching adalah fitur tambahan — tidak boleh hentikan pipeline
      console.warn("[CVE] matching failed (non-critical):", cveErr);
    }

    /* ──────────────────────────────
       6. SEVERITY CLASSIFICATION
       Mempertimbangkan CVE sekarang
    ────────────────────────────── */
    const severity =
      malicious >= 15 || abuseScore >= 80 || cveRiskScore.critical_count > 0
        ? "Critical"
        : malicious >= 8 || abuseScore >= 50 || cveRiskScore.high_count > 0
          ? "High"
          : malicious >= 3 || cveRiskScore.score > 40
            ? "Medium"
            : "Low";

    // ── VT TAGS (diperbarui) ──────────────────────────────────
    const vtTags: string[] = [];

    // 🆕 Prioritaskan tags yang sudah diparse dari virustotal.ts
    if (vt.virustotal?.tags && Array.isArray(vt.virustotal.tags)) {
      vt.virustotal.tags.forEach((tag: string) => vtTags.push(tag));
    }

    // Scan vendors sebagai tambahan
    if (vt.vendors && Array.isArray(vt.vendors)) {
      vt.vendors.forEach((vendor: any) => {
        const result = vendor.result?.toLowerCase?.() || "";
        const category = vendor.category?.toLowerCase?.() || "";

        if (result.includes("phish") || category.includes("phishing"))
          vtTags.push("phishing");
        if (result.includes("trojan") || result.includes("malware"))
          vtTags.push("trojan");
        if (result.includes("botnet") || result.includes("c2"))
          vtTags.push("c2");
        if (result.includes("ransom")) vtTags.push("ransomware");
      });
    }

    const mergedTags = [...(mispData?.tags ?? []), ...vtTags];
    const uniqueTags = [...new Set(mergedTags)];

    /* ──────────────────────────────
       8. NORMALIZE → MITIGATION ENGINE
    ────────────────────────────── */
    const normalized = {
      type,
      vt_score: malicious,
      vt_total: totalVendors,
      abuse_score: abuseScore,
      misp_confidence: (mispData?.confidence ?? "Low") as
        | "High"
        | "Medium"
        | "Low",
      tags: uniqueTags,
    };

    const confidence = calculateConfidence(normalized);
    const threatIntel = await analyzeThreatToMitigation(normalized);

    const mitreMitigations = threatIntel.mitigations ?? [];
    const mitreTechniques = [
      ...new Set(
        (threatIntel.techniques || [])
          .map((t: any) => t.technique)
          .filter(Boolean),
      ),
    ];
    const mitreName = threatIntel.primaryTechniqueName;

    /* ──────────────────────────────
       9. EXPLAINABILITY
    ────────────────────────────── */
    const reasoning = [
      `VT detections: ${malicious}/${totalVendors}`,
      `Abuse score: ${abuseScore}%`,
      `MISP confidence: ${mispData?.confidence || "Low"}`,
      `CVE matches: ${cveMatches.length} (risk score: ${cveRiskScore.score}/100)`,
    ].join("\n");

    /* ──────────────────────────────
       10. CORRELATION ENGINE
       Sekarang menerima cveMatches & cveRiskScore
    ────────────────────────────── */
    const correlationInsights = generateCorrelationInsights({
      malicious,
      totalVendors,
      abuseScore,
      totalReports,
      mispData,
      type,
      cveMatches,
      cveRiskScore,
    });

    /* ===============================
       AI REPORT
    ============================== */
    // server.ts — bagian AI REPORT
    const aiAnalysis = await generateReportAI({
      reportId,
      type,
      indicator,
      malicious,
      suspicious,
      harmless,
      undetected,
      abuseScore,
      totalReports,
      totalVendors,
      mispData,
      cveMatches, // ✅ sudah ada dari matchCVE() di atas
      cveRiskScore, // ✅ sudah ada dari calculateCVERiskScore() di atas
      correlationInsights,
      mitreData: threatIntel,
      whoisData, // ← TAMBAH INI
      history: vt.virustotal?.history ?? null, // ← TAMBAH
      pe_header: vt.virustotal?.pe_header ?? null, // ← TAMBAH
      abuseipdb, // ← TAMBAH
    });
    /* ── Threat Level untuk history ── */
    const threatLevel = vt.threatLevel || severity;

    /* ── Simpan ke history & broadcast WS ── */ // ← TAMBAH BLOK INI
    const historyEntry = {
      reportId,
      username,
      email,
      ioc: indicator,
      iocType: type,
      threatLevel,
      aiAnalysis,
      createdAt: now.toISOString(),
    };
    saveToHistory(historyEntry);
    broadcastNewReport(historyEntry);

    /* ===============================
       FINAL RESPONSE
    ============================== */
    return c.json({
      success: true,
      reportId,
      severity,
      aiAnalysis,
      correlationInsights,
      vtData: vt,
      abuseipdb,
      mispData,
      confidence,
      reasoning,
      cve: threatIntel.cve,
      cwe: threatIntel.cwe,
      mitreMitigations: threatIntel.mitigations,
      mitreTechniques,
      mitreTechniqueName: mitreName,
      mitigationActions: mitreMitigations.map((m) => m.name),
      nvdData,
      virusTotalIntel: vt.virustotal ?? null,
      cveMatches,
      cveRiskScore,
      whoisData,
      history: vt.virustotal?.history ?? null, // ← TAMBAH
      pe_header: vt.virustotal?.pe_header ?? null, // ← TAMBAH
    });
  } catch (err) {
    console.error(err);
    return c.json({ error: "Failed to generate report" }, 500);
  }
});

/* ===============================
   VT RAW ANALYZE
============================== */
app.post("/api/analyze", async (c) => {
  try {
    const body = await c.req.json();

    const { indicator, type } = body;

    if (!indicator || !type) {
      return c.json(
        {
          error: "indicator dan type diperlukan",
        },
        400,
      );
    }

    const data = await fetchVirusTotal(indicator, type);

    return c.json(data);
  } catch (error) {
    console.error(error);

    return c.json(
      {
        error: "Failed to fetch VirusTotal data",
      },
      500,
    );
  }
});

/* ===============================
   CHECK IP
============================== */
app.post("/check-ip", async (c) => {
  try {
    const body = await c.req.json();

    const ip = body.ip;

    if (!ip) {
      return c.json(
        {
          error: "IP address diperlukan",
        },
        400,
      );
    }

    if (!net.isIP(ip)) {
      return c.json(
        {
          error: "Format IP tidak valid",
        },
        400,
      );
    }

    const abuse = await getAbuseIPDB(ip);

    if (!abuse) {
      return c.json(
        {
          error: "Gagal mengambil data dari AbuseIPDB",
        },
        500,
      );
    }

    const fallback = await getLocationFallback(ip);

    const score = abuse.abuse_confidence_score || 0;
    const reports = abuse.total_reports || 0;

    const country = abuse.country_code || fallback?.country;
    const city = fallback?.city || "-";
    const asn = fallback?.org || "Unknown";

    let status = "Aman";

    if (score > 50) {
      status = "Berbahaya";
    } else if (score > 10) {
      status = "Mencurigakan";
    }

    return c.json({
      ip,
      score,
      reports,
      status,
      country: country || "-",
      city: city || "-",
      isp: abuse.isp || fallback?.org || "-",
      usage_type: abuse.usage_type || "-",
      domain: abuse.domain || "-",
      asn: asn || "Unknown",
      numDistinctUsers: abuse.numDistinctUsers || 0,
      last_reported_at: abuse.last_reported_at || null,
      recent_reports: abuse.recent_reports || [],
      abuse_categories: abuse.abuse_categories || [],
    });
  } catch (error) {
    console.error(error);

    return c.json(
      {
        error: "Failed to check IP reputation",
      },
      500,
    );
  }
});

/* ===============================
   SERVER START
============================== */
const PORT = Number(process.env.PORT) || 5000;

const server = serve({ fetch: app.fetch, port: PORT }) as Server; // ← UBAH
initWSS(server);

console.log(`Server running on http://localhost:${PORT}`);
