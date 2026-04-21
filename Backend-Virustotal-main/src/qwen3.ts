import OpenAI from "openai";

export async function generateReportAI(data: any) {
  const client = new OpenAI({
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY,
  });

  const {
    type,
    indicator,
    malicious,
    suspicious,
    harmless,
    undetected,
    abuseScore,
    totalReports,
    mispData,
  } = data;

  const totalVendors = malicious + suspicious + harmless + undetected;

  const isIP =
    type?.toLowerCase() === "ip" || type?.toLowerCase() === "ip-address";

  const abuseSection = isIP
    ? `
### AbuseIPDB Summary

- Confidence Score: ${abuseScore}%
- Reports: ${totalReports}

Reputation Verdict:
[FILL]
`
    : "";

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

  const prompt = `
You are a senior cybersecurity threat intelligence analyst.

Generate a PROFESSIONAL COMPREHENSIVE THREAT INTELLIGENCE REPORT.

STRICT RULES:
- Follow EXACT structure below
- Do NOT add extra text outside format
- Use professional SOC / CTI language
- Keep formatting clean
- Use concise intelligence wording
- Use MISP data only in ONE dedicated section
- Do not repeat MISP information elsewhere
- If MISP matchCount = 0 then state no community correlation
- If threat actor exists mention attribution possibility
- If published = true treat as validated intelligence
- If indicator is NOT IP address, completely omit AbuseIPDB section

MARKDOWN RULES:
Use **bold** ONLY for:
- LOW / MEDIUM / HIGH / CRITICAL
- Threat verdicts
- Final recommendations
- Important classifications

FORMAT:

# COMPREHENSIVE THREAT INTELLIGENCE REPORT

## EXECUTIVE SUMMARY

Analysis of ${type.toUpperCase()}: ${indicator}

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

Detection Rate: **[CALCULATE %]**

Vendor Consensus:
[SHORT ANALYSIS]

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

Community Intelligence Assessment: **[FILL]**

---

## 4. INDICATORS OF COMPROMISE (IOC)

Primary IOC:

- Type: ${type}
- Value: ${indicator}
- Status: **[MALICIOUS / SUSPICIOUS / CLEAN]**

Associated Risk Factors:

- [WRITE RISK FACTOR]
- [WRITE RISK FACTOR]
- [WRITE RISK FACTOR]

---

## 5. CONCLUSION

[WRITE SHORT PROFESSIONAL CONCLUSION]

Analyst Recommendation: **[ACTION]**

Next Review: [TIMEFRAME]

---

Report ID: ${Date.now().toString(36).toUpperCase()}

Classification: CONFIDENTIAL
`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    messages: [
      {
        role: "user",
        content: prompt,
      },
    ],
  });

  return completion.choices?.[0]?.message?.content || "No response";
}