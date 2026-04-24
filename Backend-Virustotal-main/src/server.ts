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
  mapToMITRE,
  getMitigationsByTechnique
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

    /* VT */
    const vt = await fetchVirusTotal(indicator, type);

    /* Abuse */
    let abuse = null;

    if (type === "ip") {
      abuse = await checkIP(indicator);
    }

    const abuseData = abuse?.data || {};

    /* MISP */
    const mispData = await searchMISP(indicator);

    const stats = vt.stats || {};

    const malicious = stats.malicious || 0;

    const suspicious = stats.suspicious || 0;

    const harmless = stats.harmless || 0;

    const undetected = stats.undetected || 0;

    const abuseScore = abuseData.abuseConfidenceScore || 0;

    const totalReports = abuseData.totalReports || 0;

    const totalVendors = malicious + suspicious + harmless + undetected;
    /* ===============================
      🔥 NORMALIZATION (NEW)
    ================================ */
    const normalized = {
      type,
      vt_score: malicious,
      vt_total: totalVendors,
      abuse_score: abuseScore,
      misp_confidence: mispData?.confidence || "Low",
      tags: mispData?.tags || []
    };

        /* ===============================
      🔥 MITIGATION + CONFIDENCE (NEW)
    ================================ */
    const confidence = calculateConfidence(normalized);

    // 🔥 mapping ke technique (T-code)
    const mitreTechnique = mapToMITRE(normalized);

    // 🔥 ambil mitigation dari MITRE ATT&CK
    let mitreMitigations: any[] = [];

    if (mitreTechnique) {
      mitreMitigations = await getMitigationsByTechnique(mitreTechnique);
    }

    // 🔥 fallback sederhana kalau kosong
    const fallbackMitigation = mitreMitigations.length
      ? []
      : ["No MITRE mitigation found, use general security best practices"];

    /* ===============================
      🔥 EXPLAINABILITY (NEW)
    ================================ */
    const reasoning = [
      `VT detections: ${malicious}/${totalVendors}`,
      `Abuse score: ${abuseScore}%`,
      `MISP confidence: ${mispData?.confidence || "Low"}`
    ].join("\n");


    /* Correlation */
    const correlationInsights = [
      `VirusTotal flagged ${malicious} malicious detections`,
      `AbuseIPDB score ${abuseScore}% with ${totalReports} reports`,
      `MISP matched ${mispData.matchCount} threat events`,
    ].join("\n");

    /* AI Report */
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

    return c.json({
      success: true,
      aiAnalysis,
      correlationInsights,
      vtData: vt,
      abuseData,
      mispData,
      confidence,
      mitreTechnique,
      mitreMitigations,
      fallbackMitigation,
      reasoning
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
