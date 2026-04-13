import dotenv from "dotenv";
dotenv.config();
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import net from "net";

import { fetchVirusTotal } from "./virustotal.js";
import { checkIP, getLocationFallback } from "./abuseipdb.js";
import { generateReportAI } from "./qwen3.js";
const app = new Hono();

app.use("*", cors());

/* ===============================
   🌐 ROOT
================================ */
app.get("/", (c) => {
  return c.text("Backend Threat Intelligence API running");
});

/* ===============================
   🤖 QWEN AI CHAT
================================ */
app.post("/chat", async (c) => {
  try {
    const { indicator, type } = await c.req.json();

    if (!indicator || !type) {
      return c.json({ error: "indicator & type required" }, 400);
    }

    // 🔥 1. ambil data VT
    const vt = await fetchVirusTotal(indicator, type);

    // 🔥 2. ambil data AbuseIPDB
    let abuse = null;
    if (type === "ip") {
      abuse = await checkIP(indicator);
    }

    const abuseData = abuse?.data || {};

    // 🔥 3. extract data
    const stats = vt.stats;

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;

    const abuseScore = abuseData.abuseConfidenceScore || 0;
    const totalReports = abuseData.totalReports || 0;
    const totalVendors = malicious + suspicious + harmless + undetected;
    const threatLevel =
      malicious > 0 ? "HIGH" : suspicious > 0 ? "MEDIUM" : "LOW";

    // 🔥 4. generate report (BACKEND!)
    const aiAnalysis = await generateReportAI({
      type,
      indicator,
      malicious,
      suspicious,
      abuseScore,
      totalReports,
      harmless,
      undetected,
      totalVendors,
    });

    return c.json({
      success: true,
      aiAnalysis,
      vtData: vt,
      abuseData: abuseData,
    });
  } catch (err) {
    console.error(err);
    return c.json({ error: "Failed generate report" }, 500);
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

app.get('/api/:type/:value', async (c) => {
  try {
    const type = c.req.param('type');
    const value = c.req.param('value');

    if (!type || !value) {
      return c.json({ error: "Invalid request" }, 400);
    }

    // 🔥 VirusTotal
    const vt = await fetchVirusTotal(value, type);

    // 🔥 AbuseIPDB (hanya untuk IP)
    let abuseData = null;
    if (type === "ip") {
      const abuse = await checkIP(value);
      abuseData = abuse?.data || {};
    }

    return c.json({
      success: true,
      type,
      value,
      stats: vt.stats,
      vendors: vt.vendors,
      vtData: vt,
      abuseData: abuseData,
    });

  } catch (error) {
    console.error(error);
    return c.json({ error: "Failed to fetch data" }, 500);
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
