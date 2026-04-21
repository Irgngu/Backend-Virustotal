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

    /* Correlation */
 let insights = [];

// --- Ratios & derived values ---
const vtRatio = malicious / Math.max(totalVendors, 1);

// --- 1. VirusTotal insight ---
if (vtRatio > 0.3) {
  insights.push(
    `High confidence malicious detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%).`
  );
} else if (vtRatio > 0.1) {
  insights.push(
    `Moderate detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), suggesting a potentially emerging or evasive threat.`
  );
} else {
  insights.push(
    `Low detection: Only ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), indicating low visibility or a new threat.`
  );
}

// --- 2. AbuseIPDB insight ---
if (abuseScore > 70) {
  insights.push(
    `High abuse confidence: Score ${abuseScore}% with ${totalReports} reports, indicating active malicious usage in real-world environments.`
  );
} else if (abuseScore > 30) {
  insights.push(
    `Moderate abuse activity: Score ${abuseScore}% with ${totalReports} reports, suggesting suspicious but not fully confirmed malicious behavior.`
  );
} else {
  insights.push(
    `Low abuse activity: Score ${abuseScore}% with ${totalReports} reports, indicating limited or no widespread abuse.`
  );
}

// --- 3. MISP insight ---
if (mispData.matchCount > 0) {
  insights.push(
    `Threat intelligence correlation: ${mispData.matchCount} matching event(s) found in MISP, linking this indicator to known campaigns.`
  );
} else {
  insights.push(
    `No threat intelligence correlation: 0 matches found in MISP, indicating no known association with tracked campaigns.`
  );
}

// --- 4. FINAL SUMMARY (Executive insight) ---
let finalAssessment = "";

if (vtRatio > 0.3 && abuseScore > 50) {
  finalAssessment =
    "Overall Assessment: HIGH RISK — Strong multi-source correlation confirms this indicator is actively malicious.";
} else if (vtRatio > 0.1 || abuseScore > 40 || mispData.matchCount > 0) {
  finalAssessment =
    "Overall Assessment: MEDIUM RISK — Partial correlation detected. Further monitoring and defensive action recommended.";
} else {
  finalAssessment =
    "Overall Assessment: LOW RISK — Limited evidence of malicious activity, but continued observation is advised.";
}

insights.push(finalAssessment);

// --- Final output ---
const correlationInsights = insights.join("\n\n");

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
