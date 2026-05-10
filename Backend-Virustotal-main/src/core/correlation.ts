// src/core/correlation.ts

import type { CVEMatchResult, CVERiskScore } from "../services/cve.js";

// ══════════════════════════════════════════════════════
// TYPES — diperluas dari versi sebelumnya
// ══════════════════════════════════════════════════════

type MISPData = {
  matchCount?: number;
  confidence?: string | null;
  threatLevel?: string | null;
  threatActor?: string | null;
  tags?: string[];
  score?: number;
};

type CorrelationInput = {
  malicious: number;
  totalVendors: number;
  abuseScore: number;
  totalReports: number;
  mispData: MISPData;
  // ← BARU
  cveMatches?: CVEMatchResult[];
  cveRiskScore?: CVERiskScore;
};

// ══════════════════════════════════════════════════════
// MAIN FUNCTION
// ══════════════════════════════════════════════════════

export function generateCorrelationInsights({
  malicious,
  totalVendors,
  abuseScore,
  totalReports,
  mispData,
  cveMatches = [],
  cveRiskScore,
}: CorrelationInput): string {
  const insights: string[] = [];

  const vtRatio = malicious / Math.max(totalVendors, 1);

  // ── 1. VirusTotal ──────────────────────────────────
  if (vtRatio > 0.3) {
    insights.push(
      `High confidence malicious detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%).`,
    );
  } else if (vtRatio > 0.1) {
    insights.push(
      `Moderate detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), suggesting a potentially emerging or evasive threat.`,
    );
  } else {
    insights.push(
      `Low detection: Only ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), indicating low visibility or a new threat.`,
    );
  }

  // ── 2. AbuseIPDB ───────────────────────────────────
  if (abuseScore > 70) {
    insights.push(
      `High abuse confidence: Score ${abuseScore}% with ${totalReports} reports, indicating active malicious usage in real-world environments.`,
    );
  } else if (abuseScore > 30) {
    insights.push(
      `Moderate abuse activity: Score ${abuseScore}% with ${totalReports} reports, suggesting suspicious but not fully confirmed malicious behavior.`,
    );
  } else {
    insights.push(
      `Low abuse activity: Score ${abuseScore}% with ${totalReports} reports, indicating limited or no widespread abuse.`,
    );
  }

  // ── 3. MISP ────────────────────────────────────────
  if ((mispData.matchCount || 0) > 0) {
    insights.push(
      `Threat intelligence correlation: ${mispData.matchCount} matching event(s) found in MISP, linking this indicator to known campaigns.`,
    );
  } else {
    insights.push(
      `No threat intelligence correlation: 0 matches found in MISP, indicating no known association with tracked campaigns.`,
    );
  }

  // ── 4. CVE Correlation (BARU) ──────────────────────
  if (cveMatches.length > 0) {
    const criticals = cveMatches.filter(
      (c) => c.detail?.cvss_severity === "CRITICAL",
    );
    const highs = cveMatches.filter((c) => c.detail?.cvss_severity === "HIGH");
    const exploitables = cveMatches.filter(
      (c) => c.detail?.exploit_available === true,
    );
    const networkVecs = cveMatches.filter(
      (c) => c.detail?.cvss_metrics?.attack_vector === "NETWORK",
    );
    const highestCVSS = cveRiskScore?.highest_cvss ?? 0;

    // Summary baris per CVE
    const cveSummaryLines = [
      `CVE correlation identified ${cveMatches.length} related vulnerabilit${cveMatches.length > 1 ? "ies" : "y"}:`,
    ];

    cveMatches.slice(0, 3).forEach((c) => {
      const score = c.detail?.cvss_score ?? "N/A";
      const sev = c.detail?.cvss_severity ?? "UNKNOWN";
      const exploit = c.detail?.exploit_available ? " — PUBLIC EXPLOIT ⚠️" : "";
      const patch = c.detail?.patch_available ? " [PATCH ✅]" : " [NO PATCH]";
      cveSummaryLines.push(
        `  • ${c.cve_id} | CVSS ${score} (${sev})${exploit}${patch} | Source: ${c.source}`,
      );
    });

    if (cveMatches.length > 3) {
      cveSummaryLines.push(`  • ...and ${cveMatches.length - 3} more CVE(s).`);
    }

    insights.push(cveSummaryLines.join("\n"));

    // Severity narrative
    if (criticals.length > 0) {
      insights.push(
        `CRITICAL vulnerability exposure: ${criticals.length} CRITICAL CVE(s) linked ` +
          `(highest CVSS: ${highestCVSS}). Immediate patching and containment strongly recommended.`,
      );
    } else if (highs.length > 0) {
      insights.push(
        `HIGH severity vulnerability: ${highs.length} HIGH CVE(s) linked ` +
          `(highest CVSS: ${highestCVSS}). Prioritized patching recommended within 72 hours.`,
      );
    }

    // Exploit warning
    if (exploitables.length > 0) {
      const ids = exploitables.map((c) => c.cve_id).join(", ");
      insights.push(
        `Public exploit available for: ${ids}. ` +
          `Active in-the-wild exploitation is likely — treat as imminent threat.`,
      );
    }

    // Network vector note
    if (networkVecs.length > 0) {
      insights.push(
        `${networkVecs.length} CVE(s) are remotely exploitable (Attack Vector: NETWORK), ` +
          `significantly expanding the attack surface — no physical access required.`,
      );
    }
  } else {
    insights.push(
      `No CVE correlation found: No known vulnerabilities directly linked to this indicator ` +
        `from VirusTotal tags, AbuseIPDB reports, or MISP attributes.`,
    );
  }

  // ── 5. FINAL ASSESSMENT (mempertimbangkan CVE) ─────
  const hasCriticalCVE = (cveRiskScore?.critical_count ?? 0) > 0;
  const hasExploitCVE = (cveRiskScore?.exploit_count ?? 0) > 0;
  const cveScore = cveRiskScore?.score ?? 0;

  let finalAssessment: string;

  if (
    (vtRatio > 0.3 && abuseScore > 50) ||
    (hasCriticalCVE && hasExploitCVE) ||
    (vtRatio > 0.2 && hasCriticalCVE)
  ) {
    finalAssessment =
      "Overall Assessment: HIGH RISK — Strong multi-source correlation confirms this indicator is actively malicious." +
      (hasCriticalCVE && hasExploitCVE
        ? " Critical CVE with public exploit detected — immediate action required."
        : "");
  } else if (
    vtRatio > 0.1 ||
    abuseScore > 40 ||
    (mispData.matchCount || 0) > 0 ||
    cveScore > 40
  ) {
    finalAssessment =
      "Overall Assessment: MEDIUM RISK — Partial correlation detected." +
      (cveMatches.length > 0
        ? ` ${cveMatches.length} CVE(s) linked — patching and monitoring recommended.`
        : " Further monitoring and defensive action recommended.");
  } else {
    finalAssessment =
      "Overall Assessment: LOW RISK — Limited evidence of malicious activity." +
      (cveMatches.length > 0
        ? " Note: CVE(s) detected but without strong exploitation evidence."
        : " Continued observation is advised.");
  }

  insights.push(finalAssessment);

  return insights.join("\n\n");
}
