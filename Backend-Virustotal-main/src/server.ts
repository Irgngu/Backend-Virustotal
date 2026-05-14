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
import { getAbuseIPDB, getLocationFallback, CATEGORY_MAP } from "./services/abuseipdb.js";
import { generateReportAI } from "./services/qwen3.js";
import { searchMISP } from "./services/misp.js";
import {
  analyzeThreatToMitigation,
} from "./services/mitigation.js";
import {
  matchCVE,
  calculateCVERiskScore,
  type CVEMatchResult,
  type CVERiskScore,
} from "./services/cve.js";
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
      return c.json({ error: "indicator & type required" }, 400);
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
        const result = vendor.result || "";

        vtTags.push(...extractVendorTags(result));
      });
    }

    const mergedTags = [...(mispData?.tags ?? []), ...vtTags];
    const uniqueTags = [...new Set(mergedTags)];

    function normalizeTags(tags: string[] = []): string[] {
      return [...new Set(
        tags
          .map((t) =>
            String(t)
              .toLowerCase()
              .trim()
              .replace(/[_\s]+/g, "-")
          )
          .filter(Boolean)
      )];
    }
    
    function extractVendorTags(result: string): string[] {
    const text = result.toLowerCase();

    const patterns: Record<string, RegExp[]> = {
      trojan: [
        /\btrojan\b/,
        /\btroj\b/,
        /\btrj\b/,
        /\btr\./,
      ],

      ransomware: [
        /\bransom\b/,
        /\bcrypt\b/,
        /\blocker\b/,
        /\bwannacry\b/,
        /\blocky\b/,
        /\bcerber\b/,
      ],

      backdoor: [
        /\bbackdoor\b/,
        /\bback\./,
        /\bbckdr\b/,
        /\bbdoor\b/,
      ],

      downloader: [
        /\bdownloader\b/,
        /\bdownload\b/,
        /\bdwnldr\b/,
        /\bdldr\b/,
      ],

      dropper: [
        /\bdropper\b/,
        /\bdrop\b/,
        /\bdrp\b/,
      ],

      spyware: [
        /\bspyware\b/,
        /\bspy\b/,
        /\bkeylog\b/,
        /\blogger\b/,
      ],

      adware: [
        /\badware\b/,
        /\badload\b/,
        /\badvert\b/,
        /\badbrowser\b/,
      ],

      worm: [
        /\bworm\b/,
        /\bwrm\b/,
        /\bautorun\b/,
      ],

      cryptominer: [
        /\bminer\b/,
        /\bcoinminer\b/,
        /\bbitcoin\b/,
        /\bcrypto\b/,
        /\bxmrig\b/,
        /\bcoinhive\b/,
      ],

      stealer: [
        /\bstealer\b/,
        /\bsteal\b/,
        /\binfo\b/,
        /\bpwstealer\b/,
        /\bpws\b/,
      ],

      banker: [
        /\bbanker\b/,
        /\bbank\b/,
        /\bzbot\b/,
        /\bzeus\b/,
        /\bdridex\b/,
        /\bemotet\b/,
      ],

      rat: [
        /\brat\b/,
        /\bremoteadmin\b/,
        /\bnjrat\b/,
        /\bdarkcomet\b/,
        /\bnanocore\b/,
        /\bremote[-_\s]?access[-_\s]?trojan\b/,
      ],

      rootkit: [
        /\brootkit\b/,
        /\broot\b/,
        /\bbootkit\b/,
      ],

      exploit: [
        /\bexploit\b/,
        /\bexp\b/,
        /\bcve-/,
        /\bshellcode\b/,
      ],

      pua: [
        /\bpua\b/,
        /\bunwanted\b/,
        /\bpotentially\b/,
        /\bpup\b/,
        /\briskware\b/,
        /\bhacktool\b/,
      ],

      phishing: [
        /\bphish/,
      ],

      botnet: [
        /\bbotnet\b/,
      ],

      c2: [
        /\bc2\b/,
        /command[-_\s]?and[-_\s]?control/,
      ],

      malware: [
        /\bmalware\b/,
      ],

      loader: [
        /\bloader\b/,
      ],

      keylogger: [
        /\bkeylogger\b/,
      ],
    };

    const found: string[] = [];

    for (const [tag, regexes] of Object.entries(patterns)) {
      if (regexes.some((r) => r.test(text))) {
        found.push(tag);
      }
    }

    return found;
  }
    /* ──────────────────────────────
       8. NORMALIZE → MITIGATION ENGINE
    ────────────────────────────── */
    const normalized = {
      type,
      tags: normalizeTags([
        ...uniqueTags,
        ...(abuseipdb?.recent_reports?.flatMap((r: any) =>
          (r.categories ?? [])
            .map((id: number) => CATEGORY_MAP[id])
            .filter(Boolean)
        ) ?? []),
      ]),
    };

    const threatIntel = await analyzeThreatToMitigation(normalized);

    const mitreMitigations = threatIntel.mitigations ?? [];
    const mitreTechniques = [
      ...new Set(
        (threatIntel.techniques || [])
          .map((t: any) => t.technique)
          .filter(Boolean)
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
      cveMatches,
      cveRiskScore,
    });
    /* ===============================
       AI REPORT
    ============================== */
    // server.ts — bagian AI REPORT
    // const aiAnalysis = await generateReportAI({
    //   type,
    //   indicator,
    //   malicious,
    //   suspicious,
    //   harmless,
    //   undetected,
    //   abuseScore,
    //   totalReports,
    //   totalVendors,
    //   mispData,
    //   cveMatches, // ✅ sudah ada dari matchCVE() di atas
    //   cveRiskScore, // ✅ sudah ada dari calculateCVERiskScore() di atas
    //   correlationInsights,
    // });

    /* ===============================
       FINAL RESPONSE
    ============================== */
    return c.json({
      success: true,
      severity,
      //aiAnalysis,
      correlationInsights,
      vtData: vt,
      abuseipdb,
      mispData,
      reasoning,
      cve: threatIntel.cve,
      cwe: threatIntel.cwe,
      mitreTechniques,
      mitreMitigations: threatIntel.mitigations,
      mitreTechniqueName: mitreName,
      mitigationActions: mitreMitigations.map((m) => m.name),
      nvdData,
      virusTotalIntel: vt.virustotal ?? null,
      cveMatches,
      cveRiskScore,
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

serve({
  fetch: app.fetch,
  port: PORT,
});

console.log(`Server running on http://localhost:${PORT}`);
