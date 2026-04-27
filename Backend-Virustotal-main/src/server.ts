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
import { checkIP, getLocationFallback } from "./services/abuseipdb.js";
import { generateReportAI } from "./services/qwen3.js";
import { searchMISP } from "./services/misp.js";
import {
  calculateConfidence,
  mapToMITRE,
  getMitigationsByTechnique,
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

import kevRoute from "./routes/kev.js";
import censysRoute from "./routes/censys.js";
// import correlationRoute from "./routes/correlation.js";

/* ===============================
   UTILS
============================== */
import { getProductInfo } from "./utils/vendorMap.js";
// console.log("CENSYS PAT:", process.env.CENSYS_PAT);
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

app.route("/api/kev", kevRoute);
app.route("/api/censys", censysRoute);
// app.route("/api/correlation", correlationRoute);

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
    let abuse = null;

    if (type === "ip") {
      abuse = await checkIP(indicator);
    }

    const abuseData = abuse?.data || {};

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

    const abuseScore = abuseData.abuseConfidenceScore || 0;

    const totalReports = abuseData.totalReports || 0;

    /* ===============================
       PRODUCT / VERSION / CENSYS
    ============================== */
    let detectedProduct = null;
    let detectedVersion = null;

    let productInfo = null;

    let nvdData = null;
    let kevData = null;
    let censysData = null;

    /* ===============================
   IOC LOOKUP (CENSYS ONLY)
============================== */

    if (type === "ip") {
      try {
        const censysRes = await fetch(
          `http://localhost:${process.env.PORT || 5000}/api/censys/${indicator}`,
        );

        censysData = await censysRes.json();

        if (censysData?.error) {
          censysData = null;
        }

        const firstService = censysData?.services?.[0];

        const firstSoftware = firstService?.software?.[0];

        detectedProduct = firstSoftware?.product || null;

        detectedVersion = firstSoftware?.version || null;

        if (detectedProduct) {
          productInfo = getProductInfo(
            `${detectedProduct} ${detectedVersion || ""}`,
          );
        } else {
          productInfo = getProductInfo(indicator);
        }
      } catch (e) {
        console.log("Censys skipped");

        productInfo = getProductInfo(indicator);
      }
    } else {
      productInfo = getProductInfo(indicator);

      try {
        const censysRes = await fetch(
          `http://localhost:${process.env.PORT || 5000}/api/censys/${indicator}`,
        );

        censysData = await censysRes.json();

        if (censysData?.error) {
          censysData = null;
        }

        const firstService = censysData?.services?.[0];

        const firstSoftware = firstService?.software?.[0];

        detectedProduct = firstSoftware?.product || null;

        detectedVersion = firstSoftware?.version || null;
      } catch (e) {
        console.log("Censys skipped");
      }
    }

    /* ===============================
       NVD SEARCH
    ============================== */
    if (productInfo?.keyword) {
      try {
        const nvdRes = await fetch(
          `http://localhost:${process.env.PORT || 5000}/api/nvd?keyword=${encodeURIComponent(productInfo.keyword)}`,
        );

        nvdData = await nvdRes.json();
      } catch (e) {
        console.log("NVD skipped");
      }
    }

    /* ===============================
       KEV CHECK
    ============================== */
    const firstCve = nvdData?.vulnerabilities?.[0]?.cve?.id;

    if (firstCve) {
      try {
        const kevRes = await fetch(
          `http://localhost:${process.env.PORT || 5000}/api/kev?cve=${firstCve}`,
        );

        kevData = await kevRes.json();
      } catch (e) {
        console.log("KEV skipped");
      }
    }
    /* ===============================
      🔥 NORMALIZATION (NEW)
    ================================ */
    const normalized = {
      type,
      vt_score: malicious,
      vt_total: totalVendors,
      abuse_score: abuseScore,
      misp_confidence: mispData?.confidence || "Low",
      tags: mispData?.tags || [],
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
      kevData,

      detectedProduct,
      detectedVersion,

      censysData,

      correlationInsights,
    });

    /* ===============================
       FINAL RESPONSE
    ============================== */
    return c.json({
      success: true,

      aiAnalysis,
      correlationInsights,

      vtData: vt,
      abuseData,
      mispData,

      detectedProduct,
      detectedVersion,
      productInfo,

      nvdData,
      kevData,
      censysData,
      confidence,
      mitreTechnique,
      mitreMitigations,
      fallbackMitigation,
      reasoning,
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

    const dataAPI = await checkIP(ip);

    if (!dataAPI || !dataAPI.data) {
      return c.json(
        {
          error: "Gagal mengambil data dari AbuseIPDB",
        },
        500,
      );
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

    return c.json({
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
