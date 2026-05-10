import OpenAI from "openai";

// ══════════════════════════════════════════════════════
// FORMATTER
// ══════════════════════════════════════════════════════
function formatReport(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/[^\x00-\x7F]+/g, "")
    .replace(/\n(.+)\n\1/g, "\n$1")
    .replace(/-{3,}/g, "---")
    .trim();
}

// ══════════════════════════════════════════════════════
// CVE BLOCK (SUDAH SESUAI ENGINE KAMU)
// ══════════════════════════════════════════════════════
function buildCVEBlock(cveMatches: any[], cveRiskScore: any): string {
  if (!cveMatches || cveMatches.length === 0) {
    return "No CVE correlation found.";
  }

  const lines: string[] = [];

  lines.push(
    `Total CVEs: ${cveMatches.length} | Highest CVSS: ${cveRiskScore?.highest_cvss ?? "N/A"} | Critical: ${cveRiskScore?.critical_count ?? 0} | Exploitable: ${cveRiskScore?.exploit_count ?? 0}`,
  );

  lines.push("");

  cveMatches.slice(0, 5).forEach((c) => {
    lines.push(
      `- ${c.cve_id} | CVSS ${c.detail?.cvss_score ?? "N/A"} (${c.detail?.cvss_severity ?? "UNKNOWN"}) | Exploit: ${c.detail?.exploit_available ? "YES" : "NO"}`,
    );
  });

  return lines.join("\n");
}

// ══════════════════════════════════════════════════════
// MISP BLOCK
// ══════════════════════════════════════════════════════
function buildMISPBlock(mispData: any): string {
  if (!mispData || mispData.matchCount === 0) {
    return "No MISP correlation found.";
  }

  return [
    `Matched Events : ${mispData.matchCount}`,
    `Confidence     : ${mispData.confidence}`,
    `Threat Level   : ${mispData.threatLevel}`,
    `Threat Actor   : ${mispData.threatActor ?? "Unknown"}`,
    `Source Org     : ${mispData.sourceOrg ?? "-"}`, // ← TAMBAH
    `Tags           : ${(mispData.tags || []).join(", ") || "-"}`,
  ].join("\n");
}

// ══════════════════════════════════════════════════════
// 🔵 MITRE HELPERS (BARU)
// ══════════════════════════════════════════════════════

function buildMitreBlock(mitreData: any): string {
  if (!mitreData) return "No MITRE ATT&CK data available.";

  const lines: string[] = [];

  // PRIMARY TECHNIQUE
  if (mitreData.primaryTechnique) {
    lines.push(
      `Primary Technique: ${mitreData.primaryTechnique} - ${mitreData.primaryTechniqueName}`,
    );
    lines.push("");
  }

  // ALL MATCHED TECHNIQUES
  if (mitreData.techniques?.length > 0) {
    lines.push("Matched Techniques:");

    mitreData.techniques.forEach((t: any) => {
      lines.push(
        `- ${t.technique} (${t.techniqueName}) | Confidence: ${t.confidence}%`,
      );

      if (t.reasons?.length > 0) {
        t.reasons.forEach((r: string) => {
          lines.push(`  • ${r}`);
        });
      }
    });

    lines.push("");
  }

  return lines.join("\n");
}

function buildMitigationBlock(mitreData: any): string {
  if (!mitreData?.mitigations || mitreData.mitigations.length === 0) {
    return "No mitigation strategies available.";
  }

  const lines: string[] = [];

  mitreData.mitigations.forEach((m: any) => {
    lines.push(`- ${m.name} (${m.id})`);
    lines.push(`  ${m.description}`);
    lines.push(`  Framework: ${m.framework}`);
    lines.push("");
  });

  return lines.join("\n");
}

function buildWHOISBlock(whoisData: any): string {
  if (!whoisData) return "No WHOIS data available.";

  const { timestamps, ip_address, cti_source, author } = whoisData;

  return [
    `IP Range   : ${ip_address.range_start} - ${ip_address.range_end} (${ip_address.cidr ?? "-"})`,
    ``,
    `Timestamps:`,
    `- Registered : ${timestamps.inetnum_created ?? "-"}`,
    `- Last Modified : ${timestamps.inetnum_last_modified ?? "-"}`,
    `- Route Active  : ${timestamps.route_created ?? "-"}`,
    ``,
    `CTI Source : ${cti_source.source}${cti_source.filtered ? " (filtered)" : ""}`,
    ``,
    `Author / Owner:`,
    `- Org Name  : ${author.org_name ?? "-"}`,
    `- Org ID    : ${author.org_id ?? "-"}`,
    `- Country   : ${author.country ?? "-"}`,
    `- Maintainers: ${author.maintainers?.join(", ") ?? "-"}`,
    `- Admin     : ${author.admin_contact ?? "-"}`,
    `- Tech      : ${author.tech_contact ?? "-"}`,
    `- Abuse Email: ${author.abuse_email ?? "-"}`,
  ].join("\n");
}

function buildHistoryBlock(history: any): string {
  if (!history) return "No history data available.";

  return [
    `Creation Time    : ${history.creation_time ?? "-"}`,
    `First Seen (ITW) : ${history.first_seen_itw ?? "-"}`,
    `First Submission : ${history.first_submission ?? "-"}`,
    `Last Submission  : ${history.last_submission ?? "-"}`,
    `Last Analysis    : ${history.last_analysis ?? "-"}`,
  ].join("\n");
}

function buildPEHeaderBlock(pe_header: any): string {
  if (!pe_header) return "No PE header data available.";

  return [
    `Target Machine      : ${pe_header.target_machine ?? "-"}`,
    `Compilation Time    : ${pe_header.compilation_timestamp ?? "-"}`,
    `Entry Point         : ${pe_header.entry_point ?? "-"}`,
    `Contained Sections  : ${pe_header.contained_sections ?? "-"}`,
  ].join("\n");
}

function buildVTOverviewBlock(data: any): string {
  const {
    indicator,
    type,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalVendors,
    detectionRate,
  } = data;

  return [
    `Indicator        : ${indicator}`,
    `Type             : ${type}`,
    `Malicious        : ${malicious}`,
    `Suspicious       : ${suspicious}`,
    `Harmless         : ${harmless}`,
    `Undetected       : ${undetected}`,
    `Total Vendors    : ${totalVendors}`,
    `Detection Rate   : ${detectionRate}%`,
  ].join("\n");
}

function buildAbuseOverviewBlock(abuseipdb: any): string {
  if (!abuseipdb) return "No AbuseIPDB data available.";

  return [
    `IP Version       : IPv${abuseipdb.ip_version ?? "-"}`,
    `Abuse Score      : ${abuseipdb.abuse_confidence_score ?? 0}%`,
    `Total Reports    : ${abuseipdb.total_reports ?? 0}`,
    `Distinct Users   : ${abuseipdb.numDistinctUsers ?? 0}`,
    `Country          : ${abuseipdb.country_code ?? "-"}`,
    `ISP              : ${abuseipdb.isp ?? "-"}`,
    `Usage Type       : ${abuseipdb.usage_type ?? "-"}`,
    `Last Reported    : ${abuseipdb.last_reported_at ?? "-"}`,
  ].join("\n");
}

// ══════════════════════════════════════════════════════
// MAIN FUNCTION
// ══════════════════════════════════════════════════════
export async function generateReportAI(data: any) {
  const client = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY,
  });

  // 🟢 [FIX ERROR DI SINI]
  const {
    indicator,
    type,

    malicious = 0,
    suspicious = 0,
    harmless = 0,
    undetected = 0,

    totalVendors = 0,

    abuseScore = 0,
    totalReports = 0,

    mispData = {},

    cveMatches = [],
    cveRiskScore = null,

    correlationInsights = "",

    // 🔥 [BARU]
    mitreData,
    reportId,
    whoisData = null, // ← TAMBAH INI
    history = null, // ← TAMBAH
    pe_header = null, // ← TAMBAH
    abuseipdb = null, // ← TAMBAH
  } = data;

  const detectionRate =
    totalVendors > 0 ? ((malicious / totalVendors) * 100).toFixed(1) : "0";

  const confidence = Math.min(
    Math.round(
      (malicious / Math.max(totalVendors, 1)) * 100 * 0.5 +
        abuseScore * 0.3 +
        (mispData.score || 0) * 0.2,
    ),
    100,
  );

  const threatLevel =
    confidence >= 70 ? "HIGH" : confidence >= 40 ? "MEDIUM" : "LOW";

  const now = new Date().toISOString();

  const cveBlock = buildCVEBlock(cveMatches, cveRiskScore);
  const mispBlock = buildMISPBlock(mispData);
  const vtOverviewBlock = buildVTOverviewBlock({
    indicator,
    type,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalVendors,
    detectionRate,
  });
  const abuseOverviewBlock = buildAbuseOverviewBlock(abuseipdb);

  // ════════════════════════════════════════════════════
  // PROMPT
  // ════════════════════════════════════════════════════
  const systemPrompt = `
You are a cybersecurity analyst.
Write a professional Threat Intelligence Report.
Use ONLY provided data.
DO NOT include "Prepared by", "Contact", organization, or author info.
Keep mitigation strategies AND MITRE ATT&CK ANALYSIS as single-line entries.

`;
  const mitreBlock = buildMitreBlock(mitreData);
  const mitigationBlock = buildMitigationBlock(mitreData);
  const whoisBlock = buildWHOISBlock(whoisData);
  const historyBlock = buildHistoryBlock(history);
  const peHeaderBlock = buildPEHeaderBlock(pe_header);
  const isFile = type === "file" || type?.startsWith("hash"); // ← TAMBAH DI SINI

  const userPrompt = `
THREAT INTELLIGENCE REPORT
--------------------------------------------------
Report ID : ${reportId}
Date: ${now}
Source: VirusTotal, AbuseIPDB, MISP, NVD, MITRE ATT&CK, RIPE WHOIS
--------------------------------------------------

EXECUTIVE SUMMARY

${correlationInsights}

--------------------------------------------------

THREAT OVERVIEW

--- VirusTotal ---

${vtOverviewBlock}

${
  !isFile
    ? `--- AbuseIPDB ---

${abuseOverviewBlock}`
    : ""
}

--------------------------------------------------

VULNERABILITY ANALYSIS

${cveBlock}

--------------------------------------------------

THREAT INTELLIGENCE (MISP)

${mispBlock}

${
  !isFile
    ? `
--------------------------------------------------

WHOIS INTELLIGENCE

${whoisBlock}

`
    : ""
}

${
  isFile
    ? `
--------------------------------------------------

FILE HISTORY

${historyBlock}

--------------------------------------------------

PE HEADER ANALYSIS

${peHeaderBlock}

`
    : ""
}

MITRE ATT&CK ANALYSIS

${mitreBlock}

--------------------------------------------------

THREAT ACTOR

${mispData?.threatActor ?? "Unknown"}

--------------------------------------------------

INDICATORS OF COMPROMISE

| Type | Indicator | Confidence |
|------|----------|-----------|
| ${type} | ${indicator} | ${confidence}/100 |

--------------------------------------------------

IMPACT ANALYSIS

Explain impact based on CVE severity and MITRE techniques.

--------------------------------------------------

MITIGATION STRATEGIES

${mitigationBlock}

--------------------------------------------------

COURSE OF ACTION

- Block indicator
- Monitor traffic
- Patch vulnerabilities

--------------------------------------------------

CONCLUSION

Summarize the threat.

--------------------------------------------------

REFERENCES

- VirusTotal
- AbuseIPDB
- MISP
- NVD
- MITRE ATT&CK
`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    temperature: 0.3,
    max_tokens: 1700, // ✅ Add this line
  });

  const raw = completion.choices?.[0]?.message?.content || "No response";

  return formatReport(raw);
}
