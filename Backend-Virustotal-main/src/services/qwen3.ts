import OpenAI from "openai";
import { randomUUID } from "crypto";

// ══════════════════════════════════════════════════════
// FORMATTER (🔥 INI YANG PALING PENTING)
// ══════════════════════════════════════════════════════

function formatReport(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n") // max 2 newline
    .replace(/[ \t]+$/gm, "") // remove trailing space
    .replace(/^\s*\n/gm, "") // remove empty start lines
    .trim();
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

function getSTIXIndicatorType(type: string): string {
  return "malicious-activity";
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
  } = data;

  const totalVendors = tv || malicious + suspicious + harmless + undetected;
  const detectionRate =
    totalVendors > 0 ? ((malicious / totalVendors) * 100).toFixed(1) : "0.0";

  const now = new Date().toISOString();
  const reportId = `report--${randomUUID()}`;
  const indicatorId = `indicator--${randomUUID()}`;

  const stixPattern = buildSTIXPattern(indicator, type);

  const stixConfidence = buildSTIXConfidence(
    malicious,
    totalVendors,
    abuseScore,
    cveRiskScore?.score ?? 0,
    mispData?.score ?? 0,
  );

  const tlp = resolveTLP(stixConfidence, mispData?.tlp ?? null);

  // ════════════════════════════════════════════════════
  // 🔥 PROMPT (SUDAH DIRAPIKAN)
  // ════════════════════════════════════════════════════

  const prompt = `
# STIX 2.1 THREAT INTELLIGENCE REPORT

---

## BUNDLE HEADER

- **type:** bundle
- **id:** ${reportId.replace("report", "bundle")}
- **spec_version:** 2.1

### SDO: report

- **id:** ${reportId}
- **created:** ${now}
- **name:** Threat Intelligence Report — ${type.toUpperCase()}: ${indicator}
- **confidence:** ${stixConfidence}
- **TLP:** ${tlp}

---

## EXECUTIVE SUMMARY

- **Target:** ${indicator}
- **Type:** ${type}
- **Detection Rate:** ${detectionRate}% (${malicious}/${totalVendors})
- **Confidence:** ${stixConfidence}/100

**Assessment:** [MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN]

---

## SDO: indicator

- **id:** ${indicatorId}
- **pattern:** \`${stixPattern}\`
- **confidence:** ${stixConfidence}

### VirusTotal

- Malicious: ${malicious}
- Suspicious: ${suspicious}
- Harmless: ${harmless}
- Undetected: ${undetected}

**Verdict:** [MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN]

---

## CONCLUSION

- Threat Level: [LOW / MEDIUM / HIGH]
- Recommendation: [ACTION]

`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    messages: [{ role: "user", content: prompt }],
  });

  const raw = completion.choices?.[0]?.message?.content || "No response";

  return formatReport(raw);
}
