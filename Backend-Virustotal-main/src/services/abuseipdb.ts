import axios from "axios";

/* ===============================
   🧠 CATEGORY MAP
================================ */
const CATEGORY_MAP: Record<number, string> = {
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

/* ===============================
   🔍 RAW CHECK (UNCHANGED)
================================ */
export async function checkIP(ip: string) {
  const ABUSE_API_KEY = process.env.ABUSE_API_KEY as string;

  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      headers: {
        Key: ABUSE_API_KEY,
        Accept: "application/json",
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 365,
        verbose: true,
      },
    });

    return res.data;
  } catch (error) {
    console.error("AbuseIPDB Error:", error);
    return null;
  }
}

/* ===============================
   🧹 FORMATTER (NEW)
================================ */
function formatAbuseIPDB(api: any) {
  if (!api) return null;

  const reports = Array.isArray(api.reports) ? api.reports : [];

  const sortedReports = reports.sort(
    (a: any, b: any) =>
      new Date(b.reportedAt).getTime() - new Date(a.reportedAt).getTime(),
  );

  const uniqueCategories: number[] = Array.from(
    new Set(
      reports.flatMap((r: any) => {
        if (Array.isArray(r.categories)) {
          return r.categories;
        }
        return [];
      }),
    ),
  );

  return {
    ip: api.ipAddress || null,
    abuse_confidence_score: api.abuseConfidenceScore || 0,
    total_reports: api.totalReports || 0,
    country_code: api.countryCode || null,
    isp: api.isp || null,
    domain: api.domain || null,
    usage_type: api.usageType || null,
    isWhitelisted: api.isWhitelisted ?? null,
    numDistinctUsers: api.numDistinctUsers || 0,

    is_tor: api.isTor || false,
    is_proxy: api.isProxy || false,
    is_vpn: api.isVpn || false,

    abuse_categories: uniqueCategories.map((id: number) => ({
      id: id,
      name: CATEGORY_MAP[id] || "Unknown",
    })),

    recent_reports: sortedReports.slice(0, 5).map((r: any) => ({
      reported_at: r.reportedAt,
      comment: r.comment,
      categories: r.categories,
    })),

    last_reported_at: sortedReports[0]?.reportedAt || null,
  };
}

/* ===============================
   🚀 CLEAN API (NEW - USE THIS)
================================ */
export async function getAbuseIPDB(ip: string) {
  const raw = await checkIP(ip);

  if (!raw || !raw.data) return null;

  return formatAbuseIPDB(raw.data);
}

/* ===============================
   🌍 FALLBACK GEOLOCATION
================================ */
export async function getLocationFallback(ip: string) {
  try {
    const res = await axios.get(`https://ipinfo.io/${ip}/json`);
    return res.data;
  } catch (error) {
    console.error("Fallback Error:", error);
    return null;
  }
}