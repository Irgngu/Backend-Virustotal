import OpenAI from "openai";

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
    abuseCategories = [],
    mitreMatches = [],
    mispData = {},
  } = data;

  const totalVendors =
    Number(malicious) +
    Number(suspicious) +
    Number(harmless) +
    Number(undetected);

  const detectionRate =
    totalVendors > 0
      ? ((Number(malicious) / totalVendors) * 100).toFixed(1)
      : "0.0";

  const cleanType = String(type || "unknown").toLowerCase();

  const isIP =
    cleanType === "ip" ||
    cleanType === "ip-address" ||
    cleanType === "ipv4" ||
    cleanType === "ipv6";

  const riskIndicators = isIP
    ? `
- VirusTotal Malicious Detections: ${malicious}
- VirusTotal Suspicious Flags: ${suspicious}
- AbuseIPDB Confidence Score: ${abuseScore}%
- Total Abuse Reports: ${totalReports}
`
    : `
- VirusTotal Malicious Detections: ${malicious}
- VirusTotal Suspicious Flags: ${suspicious}
`;

  const abuseSection = isIP
    ? `
### AbuseIPDB Summary

- Confidence Score: ${abuseScore}%
- Reports: ${totalReports}
- Categories: ${
        Array.isArray(abuseCategories) && abuseCategories.length
          ? abuseCategories.join(", ")
          : "-"
      }

Reputation Verdict:
[FILL BASED ON EVIDENCE]
`
    : "";

  const mitreSection = `
## 5. MITRE ATT&CK ANALYSIS

Known Evidence Mapping:
${
  Array.isArray(mitreMatches) && mitreMatches.length
    ? mitreMatches
        .map(
          (item: any) =>
            `- ${item.tactic || "-"} | ${item.technique || "-"} | ${
              item.id || "-"
            }`,
        )
        .join("\n")
    : "- No direct mapping provided. Infer only if evidence supports it."
}

MITRE Assessment:
[FILL]

---
`;

  const prompt = `
You are a senior cybersecurity threat intelligence analyst.

Generate a PROFESSIONAL COMPREHENSIVE THREAT INTELLIGENCE REPORT.

STRICT RULES:
- Follow EXACT structure below
- Do NOT add text outside structure
- Use professional SOC / CTI language
- Use concise intelligence wording
- Be evidence-based only
- Never exaggerate risk
- VirusTotal detections alone do NOT confirm compromise
- AbuseIPDB reports indicate reputation risk, not direct proof
- If MISP data exists, use only in MISP section
- If MISP matchCount = 0, state no community correlation
- If indicator is NOT IP address, omit AbuseIPDB section entirely
- Distinguish:
  * Confirmed malicious infrastructure
  * Reputation risk
  * Opportunistic scanning
  * Suspicious unconfirmed activity
  * Low / no significant threat
- Only recommend permanent blocking if evidence is strong
- Otherwise recommend monitoring / temporary filtering / watchlist
- If evidence supports behavior patterns, map to MITRE ATT&CK

SEVERITY GUIDANCE:
- LOW = minimal evidence
- MEDIUM = moderate detections or repeated abuse
- HIGH = strong multi-source evidence
- CRITICAL = active/high-confidence malicious infrastructure

MARKDOWN RULES:
Use **bold** ONLY for:
- LOW / MEDIUM / HIGH / CRITICAL
- Final verdicts
- Final recommendations
- Important classifications

FORMAT:

# COMPREHENSIVE THREAT INTELLIGENCE REPORT

## EXECUTIVE SUMMARY

Analysis of ${String(type).toUpperCase()}: ${indicator}

This report provides a multi-source threat assessment using VirusTotal${
    isIP ? ", AbuseIPDB," : ","
  } and community intelligence correlation.

Current Threat Assessment: **[FILL]**

---

## 1. THREAT LEVEL ASSESSMENT

Overall Classification: **[FILL]**

Risk Indicators:
${riskIndicators}

Severity Rating: **[LOW / MEDIUM / HIGH / CRITICAL]**

---

## 2. TECHNICAL ANALYSIS

### Analysis Metadata

- Analysis Type: ${type}
- Target Indicator: ${indicator}
- Timestamp: ${new Date().toISOString()}

### VirusTotal Summary

- Vendors Checked: ${totalVendors}
- Malicious: ${malicious}
- Suspicious: ${suspicious}
- Harmless: ${harmless}
- Undetected: ${undetected}

Detection Rate: ${detectionRate}%

Vendor Consensus:
[FILL SHORT ANALYSIS]

${abuseSection}

---

## 3. MISP COMMUNITY INTELLIGENCE

- Match Count: ${mispData?.matchCount ?? 0}
- Confidence: ${mispData?.confidence ?? "-"}
- Threat Level: ${mispData?.threatLevel ?? "-"}
- Score: ${mispData?.score ?? 0}/100
- Threat Actor: ${mispData?.threatActor ?? "-"}
- Source Organization: ${mispData?.sourceOrg ?? "-"}
- Tags: ${mispData?.tags?.length ? mispData.tags.join(", ") : "-"}
- Published: ${mispData?.published ? "Yes" : "No"}
- First Published: ${mispData?.firstPublishDate ?? "-"}
- Last Published: ${mispData?.lastPublishDate ?? "-"}
- First Recorded Change: ${mispData?.firstRecordedChange ?? "-"}
- Last Change: ${mispData?.lastChange ?? "-"}

Community Intelligence Assessment: [FILL]

---

## 4. INDICATORS OF COMPROMISE (IOC)

Primary IOC:

- Type: ${type}
- Value: ${indicator}
- Status: **[MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN]**

Associated Risk Factors:

- [FACTOR]
- [FACTOR]
- [FACTOR]

---

${mitreSection}

## 6. CONCLUSION

Threat Summary:
[WRITE SHORT PROFESSIONAL CONCLUSION]

Confidence Level:
**[LOW / MEDIUM / HIGH]**

Analyst Recommendation:
**[WRITE ACTIONABLE RECOMMENDATION]**

Next Review:
[24 HOURS / 72 HOURS / 7 DAYS / 30 DAYS]

---

Report ID: ${Date.now().toString(36).toUpperCase()}

Classification: CONFIDENTIAL
`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    temperature: 0.3,
    messages: [
      {
        role: "user",
        content: prompt,
      },
    ],
  });

  return completion.choices?.[0]?.message?.content || "No response";
}
