import OpenAI from "openai";
import fs from "fs";
import path from "path";
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

function normalizeMarkdownHeadings(text: string): string {
  const sections = [
    "EXECUTIVE SUMMARY",
    "THREAT OVERVIEW",
    "VULNERABILITY ANALYSIS",
    "THREAT INTELLIGENCE (MISP)",
    "WHOIS INTELLIGENCE",
    "FILE HISTORY",
    "PE HEADER ANALYSIS",
    "MITRE ATT&CK ANALYSIS",
    "IMPACT ANALYSIS",
    "MITIGATION STRATEGIES",
    "CONCLUSION",
    "REFERENCES",
  ];

  let result = text;

  for (const section of sections) {
    const regex = new RegExp(`^${section}$`, "gm");
    result = result.replace(regex, `## ${section}`);
  }

  result = result.replace(
    /^THREAT INTELLIGENCE REPORT$/gm,
    "# THREAT INTELLIGENCE REPORT",
  );

  return result;
}
// ══════════════════════════════════════════════════════
// CVE BLOCK
// ══════════════════════════════════════════════════════

function buildCVEBlock(cveMatches: any[], cveRiskScore: any): string {
  if (!cveMatches || cveMatches.length === 0) {
    return "No CVE correlation found.";
  }

  const lines: string[] = [];

  lines.push(
    `Total CVEs: ${cveMatches.length} | Highest CVSS: ${
      cveRiskScore?.highest_cvss ?? "N/A"
    } | Critical: ${cveRiskScore?.critical_count ?? 0} | Exploitable: ${
      cveRiskScore?.exploit_count ?? 0
    }`,
  );

  lines.push("");

  cveMatches.slice(0, 5).forEach((c) => {
    const detail = c.detail;

    lines.push(
      `- ${c.cve_id} | CVSS ${detail?.cvss_score ?? "N/A"} (${
        detail?.cvss_severity ?? "UNKNOWN"
      }) | Exploit: ${detail?.exploit_available ? "YES" : "NO"} | Patch: ${
        detail?.patch_available ? "YES" : "NO"
      }`,
    );

    if (detail?.description) {
      lines.push(`  Description: ${detail.description}`);
    }

    if (detail?.affected_versions?.length > 0) {
      lines.push("  Affected Versions:");

      detail.affected_versions.slice(0, 5).forEach((v: any) => {
        const versionRange: string[] = [];

        if (v.version && v.version !== "*") {
          versionRange.push(`Version: ${v.version}`);
        }

        if (v.versionStartIncluding) {
          versionRange.push(`Start Including: ${v.versionStartIncluding}`);
        }

        if (v.versionEndIncluding) {
          versionRange.push(`End Including: ${v.versionEndIncluding}`);
        }

        if (v.versionStartExcluding) {
          versionRange.push(`Start Excluding: ${v.versionStartExcluding}`);
        }

        if (v.versionEndExcluding) {
          versionRange.push(`End Excluding: ${v.versionEndExcluding}`);
        }

        lines.push(
          `  - ${v.vendor} ${v.product} | ${
            versionRange.length > 0 ? versionRange.join(" | ") : "Version: -"
          }`,
        );
      });
    }

    if (detail?.remediation?.length > 0) {
      lines.push("  Remediation / Patch References:");

      detail.remediation.slice(0, 5).forEach((r: any) => {
        lines.push(
          `  - ${r.source} | ${r.url} | Tags: ${r.tags?.join(", ") || "-"}`,
        );
      });
    }

    lines.push("");
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
    `Threat Level   : ${mispData.threatLevel}`,
    `Threat Actor   : ${mispData.threatActor ?? "Unknown"}`,
    `Source Org     : ${mispData.sourceOrg ?? "-"}`,
    `Tags           : ${(mispData.tags || []).join(", ") || "-"}`,
  ].join("\n");
}

// ══════════════════════════════════════════════════════
// MITRE BLOCK
// ══════════════════════════════════════════════════════

function buildMitreBlock(mitreData: any): string {
  if (!mitreData) return "No MITRE ATT&CK data available.";

  const lines: string[] = [];

  if (mitreData.primaryTechnique) {
    lines.push(
      `Primary Technique: ${mitreData.primaryTechnique} - ${mitreData.primaryTechniqueName}`,
    );
    lines.push("");
  }

  if (mitreData.techniques?.length > 0) {
    lines.push("Matched Techniques:");

    mitreData.techniques.forEach((t: any) => {
      lines.push(
        `- ${t.technique} (${t.techniqueName}) | Confidence: ${t.confidence}%`,
      );

      if (t.reasons?.length > 0) {
        t.reasons.forEach((r: string) => {
          lines.push(`  - ${r}`);
        });
      }
    });

    lines.push("");
  }

  return lines.join("\n");
}

// ══════════════════════════════════════════════════════
// MITIGATION BLOCK
// ══════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════
// WHOIS BLOCK
// ══════════════════════════════════════════════════════

function buildWHOISBlock(whoisData: any): string {
  if (!whoisData) return "No WHOIS data available.";

  if (whoisData.timestamps?.registered || whoisData.timestamps?.expiry) {
    return [
      `Timestamps:`,
      `- Registered    : ${whoisData.timestamps?.registered ?? "-"}`,
      `- Last Modified : ${whoisData.timestamps?.last_modified ?? "-"}`,
      `- Expiry Date   : ${whoisData.timestamps?.expiry ?? "-"}`,
      ``,
      `Registrant Information:`,
      `- Organization  : ${whoisData.author?.org_name ?? "-"}`,
      `- Country       : ${whoisData.author?.country ?? "-"}`,
    ].join("\n");
  }

  return [
    `Timestamps:`,
    `- Registered    : ${whoisData.timestamps?.inetnum_created ?? "-"}`,
    `- Last Modified : ${whoisData.timestamps?.inetnum_last_modified ?? "-"}`,
    `- Route Active  : ${whoisData.timestamps?.route_created ?? "-"}`,
    ``,
    `Author / Owner:`,
    `- Org Name      : ${whoisData.author?.org_name ?? "-"}`,
    `- Country       : ${whoisData.author?.country ?? "-"}`,
  ].join("\n");
}

// ══════════════════════════════════════════════════════
// HISTORY BLOCK
// ══════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════
// PE HEADER BLOCK
// ══════════════════════════════════════════════════════

function buildPEHeaderBlock(pe_header: any): string {
  if (!pe_header) return "No PE header data available.";

  return [
    `Target Machine      : ${pe_header.target_machine ?? "-"}`,
    `Compilation Time    : ${pe_header.compilation_timestamp ?? "-"}`,
    `Entry Point         : ${pe_header.entry_point ?? "-"}`,
    `Contained Sections  : ${pe_header.contained_sections ?? "-"}`,
  ].join("\n");
}

// ══════════════════════════════════════════════════════
// VIRUSTOTAL BLOCK
// ══════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════
// ABUSEIPDB BLOCK
// ══════════════════════════════════════════════════════

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
// RETRY HELPER
// ══════════════════════════════════════════════════════

async function callWithRetry(fn: () => Promise<any>, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      if (err.status === 429 && attempt < retries - 1) {
        const waitTime = err?.error?.metadata?.retry_after_seconds
          ? err.error.metadata.retry_after_seconds * 1000
          : 30000;

        console.log(
          `[AI] Rate limited. Retry in ${waitTime / 1000} seconds...`,
        );

        await new Promise((resolve) => setTimeout(resolve, waitTime));

        continue;
      }

      console.error("[AI ERROR]", err);

      throw err;
    }
  }
}

function buildReferences(data: any): string {
  const refs: string[] = [];

  // VirusTotal selalu muncul karena menjadi sumber utama overview
  refs.push("VirusTotal");

  // AbuseIPDB hanya muncul jika bukan file/hash dan datanya ada
  const isFile = data.type === "file" || data.type?.startsWith("hash");

  if (!isFile && data.abuseipdb) {
    refs.push("AbuseIPDB");
  }

  // MISP hanya muncul jika ada korelasi
  if (data.mispData && data.mispData.matchCount > 0) {
    refs.push("MISP");
  }

  // NVD hanya muncul jika ada CVE
  if (data.cveMatches && data.cveMatches.length > 0) {
    refs.push("NVD");
  }

  // MITRE hanya muncul jika ada data technique/mitigation
  if (
    data.mitreData &&
    (data.mitreData.primaryTechnique ||
      data.mitreData.techniques?.length > 0 ||
      data.mitreData.mitigations?.length > 0)
  ) {
    refs.push("MITRE ATT&CK");
  }

  // WHOIS hanya muncul jika bukan file/hash dan datanya ada
  if (!isFile && data.whoisData) {
    refs.push("WHOIS");
  }

  return [
    "--------------------------------------------------",
    "",
    "REFERENCES",
    "",
    ...refs.map((ref) => `- ${ref}`),
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

  const {
    indicator,
    type,

    malicious = 0,
    suspicious = 0,
    harmless = 0,
    undetected = 0,

    totalVendors = 0,

    abuseScore = 0,

    mispData = {},

    cveMatches = [],
    cveRiskScore = null,

    correlationInsights = "",

    mitreData,
    reportId,

    whoisData = null,
    history = null,
    pe_header = null,
    abuseipdb = null,
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

  const mitreBlock = buildMitreBlock(mitreData);
  const mitigationBlock = buildMitigationBlock(mitreData);
  const whoisBlock = buildWHOISBlock(whoisData);
  const historyBlock = buildHistoryBlock(history);
  const peHeaderBlock = buildPEHeaderBlock(pe_header);

  const isFile = type === "file" || type?.startsWith("hash");

  const systemPrompt = `
You are a cybersecurity analyst.
Write a professional Threat Intelligence Report.
IMPORTANT FORMAT RULES:
- Use Markdown format.
- Main report title MUST use "#".
- Every major section MUST use "##".
- Never write section titles as plain text.
- Never omit heading symbols.
- Preserve headings exactly.
- Use bullet lists where appropriate.
Use ONLY provided data.
DO NOT include "Prepared by", "Contact", organization, or author info.
Keep mitigation strategies AND MITRE ATT&CK ANALYSIS as single-line entries.
Add all tags from MISP data.
Use the provided CVE affected versions and remediation references if available.
`;

  const userPrompt = `
# THREAT INTELLIGENCE REPORT
--------------------------------------------------
Report ID : ${reportId}
Date: ${now}
--------------------------------------------------

## EXECUTIVE SUMMARY

${correlationInsights}

--------------------------------------------------

## THREAT OVERVIEW

--- VirusTotal ---

${vtOverviewBlock}

${
  !isFile
    ? `--- AbuseIPDB ---

${abuseOverviewBlock}`
    : ""
}

--------------------------------------------------

## VULNERABILITY ANALYSIS

${cveBlock}

Instruction:
- Explain CVE severity, affected versions, vulnerable products, patch availability, and remediation references.
- If remediation exists, mention that a vendor patch or advisory is available.
- If affected version data exists, explain which product/version range is affected.
- Do not invent versioning or remediation data.
- Preserve all original remediation URLs exactly as provided.

--------------------------------------------------

## THREAT INTELLIGENCE (MISP)

${mispBlock}

${
  !isFile
    ? `

--------------------------------------------------

## WHOIS INTELLIGENCE

${whoisBlock}
`
    : ""
}

${
  isFile
    ? `
--------------------------------------------------

## FILE HISTORY

${historyBlock}

--------------------------------------------------

## PE HEADER ANALYSIS

${peHeaderBlock}
`
    : ""
}

--------------------------------------------------

## MITRE ATT&CK ANALYSIS

${mitreBlock}

--------------------------------------------------

## IMPACT ANALYSIS

Explain impact based on CVE severity, affected versions, exploit availability, and MITRE techniques.

--------------------------------------------------

## MITIGATION STRATEGIES

${mitigationBlock}

--------------------------------------------------

## CONCLUSION

Summarize the threat.

`;

  const completion = await callWithRetry(() =>
    client.chat.completions.create({
      model: "qwen/qwen3-235b-a22b-2507",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      temperature: 0.3,
      max_tokens: 5000,
    }),
  );

  const raw = completion.choices?.[0]?.message?.content || "No response";

  const formattedReport = formatReport(raw);

  const dynamicReferences = buildReferences(data);

  const reportWithoutReferences = formattedReport.replace(
    /--------------------------------------------------\s*\n\s*REFERENCES[\s\S]*$/i,
    "",
  );

  return `${reportWithoutReferences.trim()}\n\n${dynamicReferences.trim()}`;
}
