import OpenAI from "openai";

/* ===============================
   🤖 OPTIONAL AI CLIENT
================================ */

/* ===============================
🤖 OPTIONAL AI VERSION
================================ */
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
  } = data;
  const totalVendors = malicious + suspicious + harmless + undetected;

  const prompt = `
You are a cybersecurity analyst.

Generate a COMPREHENSIVE THREAT INTELLIGENCE REPORT.

STRICT RULES:
- Follow EXACT format below
- Do NOT add extra explanation outside format
- Use clear professional language
- Keep formatting clean and structured
- Use bullet points exactly as shown
- Do NOT change section titles


FORMAT:

COMPREHENSIVE THREAT INTELLIGENCE REPORT

EXECUTIVE SUMMARY

Analysis of ${type.toUpperCase()}: ${indicator}

This automated threat intelligence report provides a comprehensive assessment based on multi-source intelligence gathering from VirusTotal and AbuseIPDB databases.

Current Threat Assessment: [FILL]

---

1. THREAT LEVEL ASSESSMENT

Overall Classification: [FILL]

Risk Indicators:
- VirusTotal Malicious Detections: ${malicious}
- VirusTotal Suspicious Flags: ${suspicious}
- AbuseIPDB Confidence Score: ${abuseScore}%
- Total Abuse Reports: ${totalReports}

Severity Rating: [LOW / MEDIUM / HIGH / CRITICAL]

---

2. DETAILED ANALYSIS

Analysis Metadata
- Analysis Type: ${type}
- Target Indicator: ${indicator}
- Analysis Timestamp: ${new Date().toISOString()}

VirusTotal Intelligence Summary
- Total Security Vendors Analyzed: ${totalVendors}
- Malicious Verdicts: ${malicious}
- Suspicious Verdicts: ${suspicious}
- Clean/Harmless: ${harmless}

Detection Rate: [CALCULATE %]

Vendor Consensus: [SHORT ANALYSIS]

AbuseIPDB Reputation Analysis
- Abuse Confidence Score: ${abuseScore}%
- Total Reports: ${totalReports}

---

3. INDICATORS OF COMPROMISE (IOCs)

Primary IOC:
- Type: ${type}
- Value: ${indicator}
- Status: [MALICIOUS / SUSPICIOUS / CLEAN]

Associated Risk Factors:
- [WRITE 2-4 BULLET POINTS]

---

4. CONCLUSION

[WRITE SHORT PROFESSIONAL CONCLUSION]

Analyst Recommendation: [ACTION]

Next Review: [TIME]

---

Report ID: ${Date.now().toString(36).toUpperCase()}
Classification: [CONFIDENTIAL / INTERNAL USE]
`;

  const completion = await client.chat.completions.create({
    model: "qwen/qwen3-32b",
    messages: [{ role: "user", content: prompt }],
  });

  return completion.choices?.[0]?.message?.content || "No response";
}
