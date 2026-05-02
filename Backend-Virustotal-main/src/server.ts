// src/server.ts

import dotenv from "dotenv";
dotenv.config();

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import net from "net";

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
/* ===============================
   CORE
============================== */
import { generateCorrelationInsights } from "./core/correlation.js";

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
    const { indicator, type } = await c.req.json();

    if (!indicator || !type) {
      return c.json(
        {
          error: "indicator & type required",
        },
        400,
      );
    }

    /* ===============================
       VIRUSTOTAL
    ============================== */
    const vt = await fetchVirusTotal(indicator, type);

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

    // Extract VT intelligence tags
    // ===============================

    const vtTags: string[] = [];

    // ambil kategori/community tags VT
    if (vt.vendors && Array.isArray(vt.vendors)) {
      vt.vendors.forEach((vendor: any) => {
        const result = vendor.result?.toLowerCase?.() || "";

        const category = vendor.category?.toLowerCase?.() || "";

        if (result.includes("phish") || category.includes("phish")) {
          vtTags.push("phishing");
        }

        // trojan / malware
        if (result.includes("trojan") || result.includes("malware")) {
          vtTags.push("trojan");
        }

        // botnet / c2
        if (result.includes("botnet") || result.includes("c2")) {
          vtTags.push("c2");
        }

        // ransomware
        if (result.includes("ransom")) {
          vtTags.push("ransomware");
        }
      });
    }

    // gabungkan semua tags
    const mergedTags = [...(mispData?.tags ?? []), ...vtTags];

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
      misp_confidence: (mispData?.confidence ?? "Low") as
        | "High"
        | "Medium"
        | "Low",

      tags: uniqueTags,
    };

    /* ── 4. CTI pipeline ── */
    const confidence = calculateConfidence(normalized);
    const threatIntel = await analyzeThreatToMitigation(normalized);

    // ✅ mitreMitigations is the full MitigationAction[] array
    const mitreMitigations = threatIntel.mitigations ?? [];

    const mitreTechnique = threatIntel.primaryTechnique;
    const mitreName = threatIntel.primaryTechniqueName;

    /* ===============================
      🔥 EXPLAINABILITY (NEW)
    ================================ */
    const reasoning = [
      `VT detections: ${malicious}/${totalVendors}`,
      `Abuse score: ${abuseScore}%`,
      `MISP confidence: ${mispData?.confidence || "Low"}`,
    ].join("\n");

    /* ===============================
       CORRELATION ENGINE
    ============================== */
    const correlationInsights = generateCorrelationInsights({
      malicious,
      totalVendors,
      abuseScore,
      totalReports,
      mispData,
      // nvdData,
      // censysData,
    });

    /* ===============================
       AI REPORT
    ============================== */
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
      mispData,
      nvdData,
      correlationInsights,
    });

    /* ===============================
       FINAL RESPONSE
    ============================== */
    return c.json({
      success: true,
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
      mitreMitigations,
      mitreTechnique,
      mitreTechniqueName: mitreName,
      mitigationActions: mitreMitigations.map((m) => m.name),
      nvdData,
    });
  } catch (err) {
    console.error(err);

    return c.json(
      {
        error: "Failed generate report",
      },
      500,
    );
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

serve({
  fetch: app.fetch,
  port: PORT,
});

console.log(`Server running on http://localhost:${PORT}`);
