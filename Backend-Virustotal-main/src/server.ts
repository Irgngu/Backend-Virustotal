import dotenv from "dotenv";
dotenv.config();
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import net from "net";

import { fetchVirusTotal } from "./virustotal.js";
import { checkIP, getLocationFallback } from "./abuseipdb.js";

import { generateReportAI } from "./qwen3.js";

import { searchMISP } from "./misp.js";
import {
  calculateConfidence,
  analyzeThreatToMitigation
} from "./mitigation.js";
import exportRoute from "./routes/export.js";


const app = new Hono();

app.use("*", cors());

app.route("/api", exportRoute);

/* ROOT */
app.get("/", (c) => c.text("Threat Intelligence API running"));

/* ===============================
   MISP ONLY
================================ */
app.post("/misp/search", async (c) => {
  try {
    const { indicator } = await c.req.json();

    if (!indicator) {
      return c.json(
        {
          error: "indicator required",
        },
        400,
      );
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
================================ */
// ================================================================
// FULL REPLACEMENT for the POST /chat handler in index.ts
// Replace everything from `app.post("/chat", async (c) => {`
// to its closing `});`
// ================================================================

app.post("/chat", async (c) => {
  try {
    const { indicator, type } = await c.req.json();

    if (!indicator || !type) {
      return c.json({ error: "indicator & type required" }, 400);
    }

    /* ── 1. Fetch all sources in parallel ── */
    const [vt, mispData] = await Promise.all([
      fetchVirusTotal(indicator, type),
      searchMISP(indicator),
    ]);

    let abuse = null;
    if (type === "ip") {
      abuse = await checkIP(indicator);
    }

    const abuseData = abuse?.data ?? {};

    /* ── 2. Build stats ── */
    const stats       = vt.stats ?? {};
    const malicious   = stats.malicious   ?? 0;
    const suspicious  = stats.suspicious  ?? 0;
    const harmless    = stats.harmless    ?? 0;
    const undetected  = stats.undetected  ?? 0;
    const abuseScore  = abuseData.abuseConfidenceScore ?? 0;
    const totalReports = abuseData.totalReports ?? 0;
    const totalVendors = malicious + suspicious + harmless + undetected;

    // ===============================
    // 🔥 SEVERITY CLASSIFICATION
    // ===============================
    const severity =
      malicious >= 15 || abuseScore >= 80
        ? "Critical"
        : malicious >= 8 || abuseScore >= 50
        ? "High"
        : malicious >= 3
        ? "Medium"
        : "Low";

    /* ── 3. Normalize for pipeline ── */
    // ===============================
// Extract VT intelligence tags
// ===============================

    const vtTags: string[] = [];

    // ambil kategori/community tags VT
    if (vt.vendors && Array.isArray(vt.vendors)) {
      vt.vendors.forEach((vendor: any) => {
        const result =
          vendor.result?.toLowerCase?.() || "";

        const category =
          vendor.category?.toLowerCase?.() || "";

        if (
          result.includes("phish") ||
          category.includes("phish")
        ) {
          vtTags.push("phishing");
        }

        // trojan / malware
        if (
          result.includes("trojan") ||
          result.includes("malware")
        ) {
          vtTags.push("trojan");
        }

        // botnet / c2
        if (
          result.includes("botnet") ||
          result.includes("c2")
        ) {
          vtTags.push("c2");
        }

        // ransomware
        if (
          result.includes("ransom")
        ) {
          vtTags.push("ransomware");
        }
      });
    }

    // gabungkan semua tags
    const mergedTags = [
      ...(mispData?.tags ?? []),
      ...vtTags,
    ];

    // remove duplicate
    const uniqueTags = [...new Set(mergedTags)];

    // ===============================
    // Normalize
    // ===============================

    const normalized = {
      type,
      vt_score: malicious,
      vt_total: totalVendors,
      abuse_score: abuseScore,
      misp_confidence:
        (mispData?.confidence ?? "Low") as
          | "High"
          | "Medium"
          | "Low",

      tags: uniqueTags,
    };

    /* ── 4. CTI pipeline ── */
    const confidence   = calculateConfidence(normalized);
    const threatIntel  = await analyzeThreatToMitigation(normalized);

    // ✅ mitreMitigations is the full MitigationAction[] array
    const mitreMitigations = threatIntel.mitigations ?? [];

    const mitreTechnique = threatIntel.primaryTechnique;
    const mitreName      = threatIntel.primaryTechniqueName;

    /* ── 5. Explainability ── */
    const reasoning = [
      `VT detections: ${malicious}/${totalVendors}`,
      `Abuse score: ${abuseScore}%`,
      `MISP confidence: ${mispData?.confidence ?? "Low"}`,
    ].join("\n");

    const correlationInsights = [
      `VirusTotal flagged ${malicious} malicious detections`,
      `AbuseIPDB score ${abuseScore}% with ${totalReports} reports`,
      `MISP matched ${mispData?.matchCount ?? 0} threat events`,
    ].join("\n");

    /* ── 6. AI report ── */
    const aiAnalysis = await generateReportAI({
      type,
      indicator,
      malicious,
      suspicious,
      harmless,
      undetected,
      abuseScore,
      totalReports,
      totalVendors,
      correlationInsights,
    });

    /* ── 7. Debug log ── */
    console.log("CTI PIPELINE →", {
      technique:         mitreTechnique,
      techniqueName:     mitreName,
      mitigationCount:   mitreMitigations.length,
      mitigationNames:   mitreMitigations.map((m) => m.name),
    });

    /* ── 8. Return ── */
    return c.json({
      success: true,
      severity,
      aiAnalysis,
      correlationInsights,
      vtData:   vt,
      abuseData,
      mispData,
      confidence,
      reasoning,
      cve: threatIntel.cve,
      cwe: threatIntel.cwe,

      // ✅ KEY FIX: send full mitigation objects — this key was MISSING before
      mitreMitigations,

      // ✅ Flat string for the frontend badge/label
      mitreTechnique,
      mitreTechniqueName: mitreName,

      // String array for any legacy consumers
      mitigationActions: mitreMitigations.map((m) => m.name),
    });

  } catch (err) {
    console.error(err);
    return c.json({ error: "Failed to generate report" }, 500);
  }
});
/* ===============================
   🔬 VIRUSTOTAL ANALYSIS
================================ */
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
   🛡 CHECK IP (ABUSEIPDB)
================================ */
app.post("/check-ip", async (c) => {
  try {
    const body = await c.req.json();
    const ip = body.ip;

    if (!ip) {
      return c.json({ error: "IP address diperlukan" }, 400);
    }

    if (!net.isIP(ip)) {
      return c.json({ error: "Format IP tidak valid" }, 400);
    }

    const dataAPI = await checkIP(ip);

    if (!dataAPI || !dataAPI.data) {
      return c.json({ error: "Gagal mengambil data dari AbuseIPDB" }, 500);
    }

    const api = dataAPI.data;
    const fallback = await getLocationFallback(ip);

    const score = api.abuseConfidenceScore || 0;
    const reports = api.totalReports || 0;

    const country = api.countryCode || fallback?.country;
    const city = api.city || fallback?.city;
    const asn = api.asn || fallback?.org;

    let status = "Aman";

    if (score > 50) {
      status = "Berbahaya";
    } else if (score > 10) {
      status = "Mencurigakan";
    }

    const result = {
      ip,
      score,
      reports,
      status,
      country: country || "-",
      city: city || "-",
      isp: api.isp || fallback?.org || "-",
      usage_type: api.usageType || "-",
      domain: api.domain || "-",
      asn: asn || "Unknown",
    };

    return c.json(result);
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
   🚀 SERVER START
================================ */
const PORT = Number(process.env.PORT) || 5000;

serve({
  fetch: app.fetch,
  port: PORT,
});

console.log(`Server running on http://localhost:${PORT}`);
