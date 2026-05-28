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
import {
  getAbuseIPDB,
  getLocationFallback,
  CATEGORY_MAP,
} from "./services/abuseipdb.js";
import { generateReportAI } from "./services/qwen3.js";
import { searchMISP } from "./services/misp.js";
import { analyzeThreatToMitigation } from "./services/mitigation.js";
import {
  matchCVE,
  calculateCVERiskScore,
  type CVEMatchResult,
  type CVERiskScore,
} from "./services/cve.js";
import { fetchWHOIS, parseDomainWHOIS } from "./services/whois.js";
import { generateOpenCTISTIX21 } from "./services/stix.js";
import { getAuthUser, supabase } from "./services/auth.js";
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
app.get("/history", async (c) => {
  try {
    const { user, profile, error } = await getAuthUser(c);

    if (error || !user) {
      return c.json(
        {
          success: false,
          error: "Unauthorized",
        },
        401,
      );
    }

    const allHistory = loadHistory();
    const isAdmin = profile?.role === "admin";

    const history = isAdmin
      ? allHistory
      : allHistory.filter((entry) => {
          if (entry.userId) {
            return entry.userId === user.id;
          }

          return entry.email === user.email;
        });

    return c.json({
      success: true,
      role: isAdmin ? "admin" : "user",
      history,
    });
  } catch (err) {
    console.error("[history]", err);

    return c.json(
      {
        success: false,
        error: "Failed to load history",
      },
      500,
    );
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

// ===============================ADMIN CHECK & ACTIVITY LOGGING (BARU)============================== */
async function requireAdminUser(c: any) {
  const { user, profile, error } = await getAuthUser(c);

  if (error || !user) {
    return {
      user: null,
      profile: null,
      response: c.json(
        {
          success: false,
          error: "Unauthorized",
        },
        401,
      ),
    };
  }

  if (profile?.role !== "admin") {
    return {
      user,
      profile,
      response: c.json(
        {
          success: false,
          error: "Forbidden: Admin access required",
        },
        403,
      ),
    };
  }

  return {
    user,
    profile,
    response: null,
  };
}

async function writeActivityLog(
  c: any,
  action: string,
  module: string,
  details?: any,
) {
  try {
    const { user } = await getAuthUser(c);

    await supabase.from("activity_logs").insert({
      user_id: user?.id ?? null,
      user_email: user?.email ?? null,
      action,
      module,
      details: details ?? {},
      ip_address:
        c.req.header("x-forwarded-for") ||
        c.req.header("cf-connecting-ip") ||
        null,
    });
  } catch (error) {
    console.error("[ACTIVITY LOG ERROR]", error);
  }
}

app.get("/admin/users", async (c) => {
  try {
    const { response } = await requireAdminUser(c);
    if (response) return response;

    const page = Number(c.req.query("page") || 1);
    const perPage = Number(c.req.query("perPage") || 50);

    const { data, error } = await supabase.auth.admin.listUsers({
      page,
      perPage,
    });

    if (error) {
      return c.json({ error: error.message }, 400);
    }

    const userIds = data.users.map((user) => user.id);

    const { data: profiles } = await supabase
      .from("profiles")
      .select("id, name, role")
      .in("id", userIds);

    const profileMap = new Map(
      profiles?.map((profile: any) => [profile.id, profile]) ?? [],
    );

    const users = data.users.map((user) => ({
      id: user.id,
      email: user.email,
      emailConfirmedAt: user.email_confirmed_at,
      createdAt: user.created_at,
      lastSignInAt: user.last_sign_in_at,
      name:
        (profileMap.get(user.id) as any)?.name ||
        user.user_metadata?.name ||
        user.user_metadata?.full_name ||
        null,
      role: (profileMap.get(user.id) as any)?.role || "user",
    }));

    await writeActivityLog(c, "VIEW_USERS", "ADMIN_USERS", {
      page,
      perPage,
    });

    return c.json({
      success: true,
      users,
    });
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Failed to fetch users",
      },
      500,
    );
  }
});
app.post("/admin/users", async (c) => {
  try {
    const { response } = await requireAdminUser(c);
    if (response) return response;

    const { email, password, name, role } = await c.req.json();

    if (!email || !password) {
      return c.json({ error: "Email and password are required" }, 400);
    }

    const selectedRole = role === "admin" ? "admin" : "user";

    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        name,
      },
    });

    if (error) {
      return c.json({ error: error.message }, 400);
    }

    await supabase.from("profiles").upsert({
      id: data.user.id,
      email,
      name: name || null,
      role: selectedRole,
      updated_at: new Date().toISOString(),
    });

    await writeActivityLog(c, "CREATE_USER", "ADMIN_USERS", {
      targetUserId: data.user.id,
      targetEmail: email,
      role: selectedRole,
    });

    return c.json({
      success: true,
      user: {
        id: data.user.id,
        email: data.user.email,
        name,
        role: selectedRole,
      },
    });
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Failed to create user",
      },
      500,
    );
  }
});
app.put("/admin/users/:id", async (c) => {
  try {
    const { response } = await requireAdminUser(c);
    if (response) return response;

    const id = c.req.param("id");
    const { email, password, name, role } = await c.req.json();

    const updatePayload: any = {};

    if (email) updatePayload.email = email;
    if (password) updatePayload.password = password;
    if (name) updatePayload.user_metadata = { name };

    if (Object.keys(updatePayload).length > 0) {
      const { error } = await supabase.auth.admin.updateUserById(
        id,
        updatePayload,
      );

      if (error) {
        return c.json({ error: error.message }, 400);
      }
    }

    const profilePayload: any = {
      id,
      updated_at: new Date().toISOString(),
    };

    if (email) profilePayload.email = email;
    if (name) profilePayload.name = name;
    if (role === "admin" || role === "user") {
      profilePayload.role = role;
    }

    await supabase.from("profiles").upsert(profilePayload);

    await writeActivityLog(c, "UPDATE_USER", "ADMIN_USERS", {
      targetUserId: id,
      updatedFields: Object.entries({ email, password, name, role })
        .filter(([, value]) => Boolean(value))
        .map(([key]) => key),
    });

    return c.json({
      success: true,
      message: "User updated successfully",
    });
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Failed to update user",
      },
      500,
    );
  }
});
app.delete("/admin/users/:id", async (c) => {
  try {
    const { user, response } = await requireAdminUser(c);
    if (response) return response;

    const id = c.req.param("id");

    if (id === user?.id) {
      return c.json({ error: "Admin cannot delete own account" }, 400);
    }

    const { error } = await supabase.auth.admin.deleteUser(id);

    if (error) {
      return c.json({ error: error.message }, 400);
    }

    await writeActivityLog(c, "DELETE_USER", "ADMIN_USERS", {
      targetUserId: id,
    });

    return c.json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Failed to delete user",
      },
      500,
    );
  }
});
app.get("/admin/activity-logs", async (c) => {
  try {
    const { response } = await requireAdminUser(c);
    if (response) return response;

    const limit = Number(c.req.query("limit") || 50);

    const { data, error } = await supabase
      .from("activity_logs")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      return c.json({ error: error.message }, 400);
    }

    await writeActivityLog(c, "VIEW_ACTIVITY_LOGS", "ADMIN_LOGS", {
      limit,
    });

    return c.json({
      success: true,
      logs: data,
    });
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Failed to fetch activity logs",
      },
      500,
    );
  }
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
    const { user, profile } = await getAuthUser(c);

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
    // ── WHOIS ─────────────────────────────
    let whoisData = null;

    // IP → RIPE WHOIS
    if (type === "ip") {
      whoisData = await fetchWHOIS(indicator);
    }

    // DOMAIN → VirusTotal WHOIS
    if (type === "domain") {
      const rawWhois = (vt?.virustotal as any)?.whois;

      if (rawWhois) {
        whoisData = parseDomainWHOIS(rawWhois);
      }
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
        const result = vendor.result || "";

        vtTags.push(...extractVendorTags(result));
      });
    }

    const mergedTags = [...(mispData?.tags ?? []), ...vtTags];
    const uniqueTags = [...new Set(mergedTags)];

    // ── ABUSEIPDB TAGS ─────────────────────────────
    const abuseTags: string[] = [];

    if (abuseipdb?.recent_reports) {
      abuseipdb.recent_reports.forEach((report: any) => {
        if (Array.isArray(report.categories)) {
          report.categories.forEach((id: number) => {
            const category = CATEGORY_MAP[id];

            if (category) {
              abuseTags.push(
                String(category).toLowerCase().replace(/\s+/g, "-"),
              );
            }
          });
        }
      });
    }

    // ── MISP TAGS ─────────────────────────────
    const mispTags: string[] = Array.isArray(mispData?.tags)
      ? mispData.tags.map((t: string) =>
          String(t)
            .toLowerCase()
            .trim()
            .replace(/[_\s]+/g, "-"),
        )
      : [];

    function normalizeTags(tags: string[] = []): string[] {
      return [
        ...new Set(
          tags
            .map((t) =>
              String(t)
                .toLowerCase()
                .trim()
                .replace(/[_\s]+/g, "-"),
            )
            .filter(Boolean),
        ),
      ];
    }

    // ── FINAL TAG GROUPING ─────────────────────────────
    const finalVirusTotalTags = normalizeTags(vtTags);

    const finalAbuseIPDBTags = normalizeTags(abuseTags);

    const finalMISPTags = normalizeTags(mispTags);

    const allCombinedTags = normalizeTags([
      ...finalVirusTotalTags,
      ...finalAbuseIPDBTags,
      ...finalMISPTags,
    ]);

    function extractVendorTags(result: string): string[] {
      const text = result.toLowerCase();

      const patterns: Record<string, RegExp[]> = {
        trojan: [/\btrojan\b/, /\btroj\b/, /\btrj\b/, /\btr\./],

        ransomware: [
          /\bransom\b/,
          /\bcrypt\b/,
          /\blocker\b/,
          /\bwannacry\b/,
          /\blocky\b/,
          /\bcerber\b/,
        ],

        backdoor: [/\bbackdoor\b/, /\bback\./, /\bbckdr\b/, /\bbdoor\b/],

        downloader: [
          /\bdownloader\b/,
          /\bdownload\b/,
          /\bdwnldr\b/,
          /\bdldr\b/,
        ],

        dropper: [/\bdropper\b/, /\bdrop\b/, /\bdrp\b/],

        spyware: [/\bspyware\b/, /\bspy\b/, /\bkeylog\b/, /\blogger\b/],

        adware: [/\badware\b/, /\badload\b/, /\badvert\b/, /\badbrowser\b/],

        worm: [/\bworm\b/, /\bwrm\b/, /\bautorun\b/],

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

        rootkit: [/\brootkit\b/, /\broot\b/, /\bbootkit\b/],

        exploit: [/\bexploit\b/, /\bexp\b/, /\bcve-/, /\bshellcode\b/],

        pua: [
          /\bpua\b/,
          /\bunwanted\b/,
          /\bpotentially\b/,
          /\bpup\b/,
          /\briskware\b/,
          /\bhacktool\b/,
        ],

        phishing: [/\bphish/],

        botnet: [/\bbotnet\b/],

        c2: [/\bc2\b/, /command[-_\s]?and[-_\s]?control/],

        malware: [/\bmalware\b/],

        loader: [/\bloader\b/],

        keylogger: [/\bkeylogger\b/],
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
      tags: allCombinedTags,
    };

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

    // /* ──────────────────────────────
    //    9. EXPLAINABILITY
    // ────────────────────────────── */
    // const reasoning = [
    //   `VT detections: ${malicious}/${totalVendors}`,
    //   `Abuse score: ${abuseScore}%`,
    //   `MISP threat level: ${mispData?.threatLevel || "Low"}`,
    //   `CVE matches: ${cveMatches.length} (risk score: ${cveRiskScore.score}/100)`,
    // ].join("\n");

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
      ...(user?.id ? { userId: user.id } : {}),
      username:
        profile?.name ||
        user?.user_metadata?.name ||
        user?.user_metadata?.full_name ||
        username,
      email: user?.email || email,
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
      // reasoning,
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
      tags: {
        virustotal: finalVirusTotalTags,
        abuseipdb: finalAbuseIPDBTags,
        misp: finalMISPTags,
        combined: allCombinedTags,
      },
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
   EXPORT STIX 2.1 JSON
============================== */
app.post("/export/stix", async (c) => {
  try {
    const body = await c.req.json();

    const stixBundle = generateOpenCTISTIX21(body);

    return c.json(stixBundle, 200, {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="opencti-stix-${body.reportId || "report"}.json"`,
    });
  } catch (error: any) {
    console.error("[STIX EXPORT ERROR]", error);

    return c.json(
      {
        error: "Failed to export STIX 2.1 JSON",
        details: error.message,
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
