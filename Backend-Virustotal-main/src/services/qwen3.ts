import OpenAI from "openai";
import { randomUUID } from "crypto";
import type { CVEMatchResult, CVERiskScore } from "../services/cve.js";

// ══════════════════════════════════════════════════════
// FORMATTER
// ══════════════════════════════════════════════════════
//BARU
function removeDuplicateLines(text: string): string {
  const seen = new Set<string>();
  const result: string[] = [];

  for (let line of text.split("\n")) {
    const clean = line.trim().toLowerCase();

    if (!clean) {
      result.push("");
      continue;
    }

    if (seen.has(clean)) continue;

    seen.add(clean);
    result.push(line);
  }

  return result.join("\n");
}
function formatReport(text: string): string {
  return (
    text
      .replace(/\r\n/g, "\n")
      .replace(/\n{3,}/g, "\n\n")

      // 🔥 REMOVE BOLD MARKDOWN (**text**)
      .replace(/\*\*(.*?)\*\*/g, "$1")

      // remove emoji
      .replace(/[\u{1F300}-\u{1FAFF}]/gu, "")

      // remove non-ascii
      .replace(/[^\x00-\x7F]+/g, "")

      // remove duplicate lines
      .replace(/\n(.+)\n\1/g, "\n$1")

      // normalize separator
      .replace(/-{3,}/g, "---")

      .replace(/[ \t]+$/gm, "")
      .trim()
  );
}

// ══════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════

function buildSTIXPattern(indicator: string, type: string): string {
  const t = type?.toLowerCase();
  if (t === "ip" || t === "ip-address")
    return `[ipv4-addr:value = '${indicator}']`;
  if (t === "domain") return `[domain-name:value = '${indicator}']`;
  if (t === "url") return `[url:value = '${indicator}']`;
  if (t === "hash" || t === "file") {
    if (indicator.length === 32) return `[file:hashes.MD5 = '${indicator}']`;
    if (indicator.length === 40)
      return `[file:hashes.'SHA-1' = '${indicator}']`;
    return `[file:hashes.'SHA-256' = '${indicator}']`;
  }
  return `[${type}:value = '${indicator}']`;
}

function buildSTIXConfidence(
  malicious: number,
  totalVendors: number,
  abuseScore: number,
  cveScore: number,
  mispScore: number,
): number {
  const vtRatio = totalVendors > 0 ? (malicious / totalVendors) * 100 : 0;
  const score =
    vtRatio * 0.4 + abuseScore * 0.25 + cveScore * 0.2 + mispScore * 0.15;
  return Math.min(Math.round(score), 100);
}

function resolveTLP(confidence: number, mispTlp: string | null): string {
  if (mispTlp) return `TLP:${mispTlp.toUpperCase()}`;
  if (confidence >= 70) return "TLP:AMBER";
  if (confidence >= 40) return "TLP:GREEN";
  return "TLP:CLEAR";
}

function resolveThreatLevel(
  confidence: number,
  hasCriticalCVE: boolean,
  hasExploit: boolean,
): string {
  if (confidence >= 70 || (hasCriticalCVE && hasExploit)) return "HIGH";
  if (confidence >= 40) return "MEDIUM";
  return "LOW";
}

// ── Build CVE summary block for prompt ────────────────
function buildCVEBlock(
  cveMatches: CVEMatchResult[],
  cveRiskScore: CVERiskScore | null,
): string {
  if (!cveMatches || cveMatches.length === 0) {
    return "No CVE correlation found for this indicator.";
  }

  const lines: string[] = [];
  const criticals = cveMatches.filter(
    (c) => c.detail?.cvss_severity === "CRITICAL",
  );
  const highs = cveMatches.filter((c) => c.detail?.cvss_severity === "HIGH");
  const exploitables = cveMatches.filter(
    (c) => c.detail?.exploit_available === true,
  );

  lines.push(
    `Total CVEs linked: ${cveMatches.length} | Highest CVSS: ${cveRiskScore?.highest_cvss ?? "N/A"} | Critical: ${cveRiskScore?.critical_count ?? 0} | Exploitable: ${cveRiskScore?.exploit_count ?? 0}`,
  );
  lines.push("");

  cveMatches.slice(0, 5).forEach((c) => {
    const score = c.detail?.cvss_score ?? "N/A";
    const sev = c.detail?.cvss_severity ?? "UNKNOWN";
    const vector = c.detail?.cvss_metrics?.attack_vector ?? "N/A";
    const exploit = c.detail?.exploit_available
      ? "PUBLIC EXPLOIT AVAILABLE"
      : "No public exploit";
    const patch = c.detail?.patch_available
      ? "Patch available"
      : "No patch yet";
    lines.push(
      `  - ${c.cve_id} | CVSS ${score} (${sev}) | Attack Vector: ${vector} | ${exploit} | ${patch} | Source: ${c.source}`,
    );
  });

  if (cveMatches.length > 5) {
    lines.push(`  - ...and ${cveMatches.length - 5} more CVE(s).`);
  }

  if (exploitables.length > 0) {
    lines.push(
      `\n  Active exploit IDs: ${exploitables.map((c) => c.cve_id).join(", ")}`,
    );
  }

  return lines.join("\n");
}

// ── Build MISP block for prompt ───────────────────────
function buildMISPBlock(mispData: Record<string, any>): string {
  if (!mispData || (mispData.matchCount ?? 0) === 0) {
    return "No matches found in MISP — no known association with tracked campaigns.";
  }
  return [
    `Matched Events : ${mispData.matchCount}`,
    `Confidence     : ${mispData.confidence ?? "N/A"}`,
    `Threat Level   : ${mispData.threatLevel ?? "N/A"}`,
    `Threat Actor   : ${mispData.threatActor ?? "Unknown"}`,
    `Tags           : ${(mispData.tags ?? []).join(", ") || "None"}`,
    `MISP Score     : ${mispData.score ?? 0}`,
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
    type,
    indicator,
    malicious = 0,
    suspicious = 0,
    harmless = 0,
    undetected = 0,
    abuseScore = 0,
    totalReports = 0,
    totalVendors: tv = 0,
    mispData = {},
    cveRiskScore = null,
    cveMatches = [],
    // Optional: caller can pre-compute correlation text
    correlationInsights = null,
    // Report metadata
    source = "VirusTotal, AbuseIPDB, MISP, NVD",
    preparedBy = "Threat Intelligence Team",
    appendix = "-",
  } = data;

  const totalVendors = tv || malicious + suspicious + harmless + undetected;
  const detectionRate =
    totalVendors > 0 ? ((malicious / totalVendors) * 100).toFixed(1) : "0.0";
  const vtRatio = totalVendors > 0 ? malicious / totalVendors : 0;

  const now = new Date();
  const reportDate = now.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "long",
    year: "numeric",
  });
  const nowISO = now.toISOString();

  const bundleId = `bundle--${randomUUID()}`;
  const reportId = `report--${randomUUID()}`;
  const indicatorId = `indicator--${randomUUID()}`;
  const relationshipId = `relationship--${randomUUID()}`;

  const stixPattern = buildSTIXPattern(indicator, type);
  const stixConfidence = buildSTIXConfidence(
    malicious,
    totalVendors,
    abuseScore,
    cveRiskScore?.score ?? 0,
    mispData?.score ?? 0,
  );
  const tlp = resolveTLP(stixConfidence, mispData?.tlp ?? null);
  const hasCriticalCVE = (cveRiskScore?.critical_count ?? 0) > 0;
  const hasExploit = (cveRiskScore?.exploit_count ?? 0) > 0;
  const threatLevel = resolveThreatLevel(
    stixConfidence,
    hasCriticalCVE,
    hasExploit,
  );

  const cveBlock = buildCVEBlock(cveMatches, cveRiskScore);
  const mispBlock = buildMISPBlock(mispData);
  console.log("[DEBUG] cveMatches:", JSON.stringify(cveMatches, null, 2));
  console.log("[DEBUG] cveBlock:", cveBlock);

  // ════════════════════════════════════════════════════
  // SYSTEM PROMPT
  // ════════════════════════════════════════════════════

  const systemPrompt = `You are a senior threat intelligence analyst. 
Your task is to write a professional Threat Intelligence Report in the exact format and style provided.

STRICT RULES:
- Follow the section order exactly as given in the template.
- Fill all [PLACEHOLDER] fields using ONLY the data provided — do NOT invent IOCs, CVEs, or threat actors.
- Write in clear, professional English. Be specific and concise.
- For sections with no data, write "No data available" — do not omit the section.
- All STIX 2.1 fields must remain intact and unmodified.
- Do NOT add markdown code blocks, backticks, or extra commentary outside the report.
- Output only the report content — nothing else.`;

  // ════════════════════════════════════════════════════
  // USER PROMPT (REPORT TEMPLATE)
  // ════════════════════════════════════════════════════

  const userPrompt = `
# THREAT INTELLIGENCE REPORT
---
**Date:** ${reportDate}
**Source:** ${source}
**Prepared by:** ${preparedBy}
**TLP:** ${tlp}
**Appendix:** ${appendix}
---

---

## STIX 2.1 BUNDLE METADATA

| Field        | Value                            |
|--------------|----------------------------------|
| type         | bundle                           |
| id           | ${bundleId}                      |
| spec_version | 2.1                              |

### SDO: report

| Field      | Value                                                         |
|------------|---------------------------------------------------------------|
| type       | report                                                        |
| id         | ${reportId}                                                   |
| created    | ${nowISO}                                                     |
| name       | Threat Intelligence Report — ${type.toUpperCase()}: ${indicator} |
| confidence | ${stixConfidence}/100                                         |
| TLP        | ${tlp}                                                        |
| object_refs| ${indicatorId}, ${relationshipId}                             |

---

## EXECUTIVE SUMMARY

Write 2–3 paragraphs summarizing:
- What this indicator is and why it is significant.
- Key threat context based on detection rate (${detectionRate}% — ${malicious}/${totalVendors} vendors), abuse score (${abuseScore}%), MISP matches (${mispData?.matchCount ?? 0}), and CVE exposure (${cveMatches.length} CVEs linked).
- Overall risk posture and urgency for the defending organization.

[AI: GENERATE EXECUTIVE SUMMARY HERE BASED ON DATA ABOVE]

---

## THREAT OVERVIEW

### Technical Details

| Field              | Value                            |
|--------------------|----------------------------------|
| Indicator          | ${indicator}                     |
| Type               | ${type.toUpperCase()}            |
| STIX Pattern       | \`${stixPattern}\`               |
| Detection Rate     | ${detectionRate}% (${malicious}/${totalVendors} vendors) |
| VT Malicious       | ${malicious}                     |
| VT Suspicious      | ${suspicious}                    |
| VT Harmless        | ${harmless}                      |
| VT Undetected      | ${undetected}                    |
| Abuse Score        | ${abuseScore}% (${totalReports} reports) |
| Confidence Score   | ${stixConfidence}/100            |
| Threat Level       | ${threatLevel}                   |

### SDO: indicator (STIX 2.1)

| Field             | Value                                                          |
|-------------------|----------------------------------------------------------------|
| type              | indicator                                                      |
| id                | ${indicatorId}                                                 |
| created           | ${nowISO}                                                      |
| pattern           | \`${stixPattern}\`                                             |
| pattern_type      | stix                                                           |
| valid_from        | ${nowISO}                                                      |
| indicator_types   | malicious-activity                                             |
| confidence        | ${stixConfidence}                                              |
| labels            | ${tlp}                                                         |

---

## CVE VULNERABILITY CORRELATION

${cveBlock}

[AI: Based on the CVE data above, write 2–3 sentences explaining the vulnerability exposure, exploitability risk, and recommended patching urgency.]

---

## THREAT INTELLIGENCE CORRELATION (MISP)

${mispBlock}

${correlationInsights ? `\n### Correlation Analysis\n\n${correlationInsights}` : "[AI: Write 1–2 sentences summarizing MISP match significance and whether this indicator links to known campaigns.]"}

---

## THREAT ACTOR ATTRIBUTION

[AI: Based on MISP threat actor field (${mispData?.threatActor ?? "Unknown"}) and tags (${(mispData?.tags ?? []).join(", ") || "none"}), describe the likely threat actor(s), their known TTPs, target sectors, and geographic focus. If no attribution data is available, state that attribution is unconfirmed and describe likely motivations inferred from the indicator type and detection context.]

---

## INDICATORS OF COMPROMISE (IOCs)

| Type       | Indicator                    | Confidence | Source              |
|------------|------------------------------|------------|---------------------|
| ${type.toUpperCase().padEnd(10)} | ${indicator.padEnd(28)} | ${stixConfidence}/100  | VirusTotal, AbuseIPDB |

[AI: If additional IOCs can be inferred from CVE or MISP data (related IPs, hashes, domains), list them here in the same table format. Otherwise state "No additional IOCs identified from available sources."]

---

## IMPACT ANALYSIS

[AI: Write 3–5 bullet points describing the potential impact if this indicator is active in an environment. Base this on: indicator type (${type}), threat level (${threatLevel}), CVE exploit status (${hasExploit ? "public exploit available" : "no public exploit"}), and MISP threat level (${mispData?.threatLevel ?? "unknown"}). Include business, operational, and compliance risks.]

---

## MITIGATION STRATEGIES

[AI: Write 4–6 specific, actionable mitigation steps tailored to this indicator type (${type}) and threat level (${threatLevel}). Include: immediate containment, detection rules, patching guidance (if CVEs present), network controls, and logging/monitoring recommendations.]

---

## STIX 2.1 RELATIONSHIP

| Field             | Value                                                          |
|-------------------|----------------------------------------------------------------|
| type              | relationship                                                   |
| id                | ${relationshipId}                                              |
| created           | ${nowISO}                                                      |
| relationship_type | indicates                                                      |
| source_ref        | ${indicatorId}                                                 |
| description       | [AI: One sentence describing what this indicator indicates]    |

---

## CONCLUSION

[AI: Write 2–3 sentences summarizing the overall threat assessment, key actions required, and the confidence level of this report. End with a risk verdict: LOW / MEDIUM / HIGH and the recommended response priority.]

---

## REFERENCES

[AI: List any relevant public references that can be cited for the CVEs, threat actors, or indicator context mentioned in this report. Format as numbered list with source name and URL. If no specific references are available, list general authoritative sources for the indicator type (e.g., NVD for CVEs, AbuseIPDB for IP reputation).]

---
*Report generated: ${nowISO} | Confidence: ${stixConfidence}/100 |  ${tlp}*
`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
  });

  const raw = completion.choices?.[0]?.message?.content || "No response";

  return formatReport(raw);
}
