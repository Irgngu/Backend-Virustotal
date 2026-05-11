// src/core/correlation.ts

import type { CVEMatchResult, CVERiskScore } from "../services/cve.js";

// ══════════════════════════════════════════════════════
// TYPES
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
  type: string; // ← BARU: "ip" | "domain" | "url" | "hash"
  cveMatches?: CVEMatchResult[];
  cveRiskScore?: CVERiskScore;
};

// ══════════════════════════════════════════════════════
// WEIGHT RESOLVER
// ══════════════════════════════════════════════════════

type WeightProfile = {
  vt: number;
  abuse: number;
  misp: number;
  label: string;
};

function resolveWeights(type: string, mispMatchCount: number): WeightProfile {
  const t = type.toLowerCase();

  // Hash or unknown domain → VT 100%
  if (
    t === "hash" ||
    t === "hash-md5" ||
    t === "hash-sha1" ||
    t === "hash-sha256" ||
    t.includes("hash")
  ) {
    return { vt: 1.0, abuse: 0.0, misp: 0.0, label: "Hash" };
  }

  // Domain, URL → VT 65%, MISP 35%
  if (t === "domain" || t === "url") {
    return { vt: 0.65, abuse: 0.0, misp: 0.35, label: "Domain/URL" };
  }

  // IP — split by MISP presence
  if (t === "ip") {
    if (mispMatchCount > 0) {
      // IP with known campaign
      return { vt: 0.5, abuse: 0.2, misp: 0.3, label: "IP (Known Campaign)" };
    } else {
      // IP without campaign
      return { vt: 0.65, abuse: 0.35, misp: 0.0, label: "IP (No Campaign)" };
    }
  }

  // Fallback: treat like IP no campaign
  return { vt: 0.65, abuse: 0.35, misp: 0.0, label: "Unknown Type" };
}

// ══════════════════════════════════════════════════════
// CONFIDENCE SCORE CALCULATOR
// ══════════════════════════════════════════════════════

function calculateWeightedScore(
  vtRatio: number, // 0–1
  abuseScore: number, // 0–100
  mispScore: number, // 0–100 (derived from matchCount)
  weights: WeightProfile,
): number {
  const vtNorm = vtRatio * 100; // normalize to 0–100
  const abuseNorm = abuseScore; // already 0–100
  const mispNorm = mispScore; // already 0–100

  const score =
    vtNorm * weights.vt + abuseNorm * weights.abuse + mispNorm * weights.misp;

  return Math.min(100, Math.round(score));
}

function classifyScore(score: number): {
  label: string;
  risk: "LOW" | "MEDIUM" | "HIGH";
} {
  if (score >= 51) return { label: "High or Malicious", risk: "HIGH" };
  if (score >= 26) return { label: "Medium or Suspicious", risk: "MEDIUM" };
  return { label: "Low or Benign", risk: "LOW" };
}

// ══════════════════════════════════════════════════════
// MAIN FUNCTION
// ══════════════════════════════════════════════════════

export function generateCorrelationInsights({
  malicious,
  totalVendors,
  abuseScore,
  totalReports,
  mispData,
  type,
  cveMatches = [],
  cveRiskScore,
}: CorrelationInput): string {
  const insights: string[] = [];

  const vtRatio = malicious / Math.max(totalVendors, 1);
  const mispMatchCount = mispData.matchCount || 0;

  // ── Resolve weights based on IoC type + MISP presence ──
  const weights = resolveWeights(type, mispMatchCount);

  // ── Derive MISP score (0–100) from matchCount ──
  // Cap at 5 matches = 100, scale linearly
  const mispScore = Math.min(100, mispMatchCount * 20);

  // ── Calculate weighted confidence score ──
  const weightedScore = calculateWeightedScore(
    vtRatio,
    abuseScore,
    mispScore,
    weights,
  );
  const classification = classifyScore(weightedScore);

  // ── 1. Weight Profile Used ──────────────────────────
  insights.push(
    `Weight profile applied [${weights.label}]: ` +
      `VirusTotal ${weights.vt * 100}% · AbuseIPDB ${weights.abuse * 100}% · MISP ${weights.misp * 100}%.`,
  );

  // ── 2. Weighted Confidence Score ───────────────────
  insights.push(
    `Weighted confidence score: ${weightedScore}/100 → Classification: ${classification.label}.`,
  );

  // ── 3. VirusTotal ──────────────────────────────────
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

  // ── 4. AbuseIPDB ───────────────────────────────────
  if (weights.abuse > 0) {
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
  } else {
    insights.push(
      `AbuseIPDB not weighted for this IoC type (${type}) — score ${abuseScore}% excluded from confidence calculation.`,
    );
  }

  // ── 5. MISP ────────────────────────────────────────
  if (mispMatchCount > 0) {
    insights.push(
      `Threat intelligence correlation: ${mispMatchCount} matching event(s) found in MISP, linking this indicator to known campaigns.`,
    );
  } else {
    insights.push(
      `No threat intelligence correlation: 0 matches found in MISP, indicating no known association with tracked campaigns.`,
    );
  }

  // ── 6. CVE Correlation ─────────────────────────────
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

    if (exploitables.length > 0) {
      const ids = exploitables.map((c) => c.cve_id).join(", ");
      insights.push(
        `Public exploit available for: ${ids}. ` +
          `Active in-the-wild exploitation is likely — treat as imminent threat.`,
      );
    }

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

  // ── 7. FINAL ASSESSMENT (weighted score + CVE) ─────
  const hasCriticalCVE = (cveRiskScore?.critical_count ?? 0) > 0;
  const hasExploitCVE = (cveRiskScore?.exploit_count ?? 0) > 0;

  let finalAssessment: string;

  if (classification.risk === "HIGH" || (hasCriticalCVE && hasExploitCVE)) {
    // Build specific CVE detail message
    let cveDetail = "";

    if (hasCriticalCVE && hasExploitCVE) {
      const criticalWithExploit = cveMatches.filter(
        (c) =>
          c.detail?.cvss_severity === "CRITICAL" &&
          c.detail?.exploit_available === true,
      );
      const criticalOnly = cveMatches.filter(
        (c) =>
          c.detail?.cvss_severity === "CRITICAL" &&
          c.detail?.exploit_available !== true,
      );
      const exploitOnly = cveMatches.filter(
        (c) =>
          c.detail?.cvss_severity !== "CRITICAL" &&
          c.detail?.exploit_available === true,
      );

      const parts: string[] = [];

      if (criticalWithExploit.length > 0) {
        const ids = criticalWithExploit.map((c) => c.cve_id).join(", ");
        const scores = criticalWithExploit
          .map((c) => `CVSS ${c.detail?.cvss_score ?? "N/A"}`)
          .join(", ");
        parts.push(
          `${ids} (${scores}) — CRITICAL severity with public exploit, active exploitation likely.`,
        );
      }

      if (criticalOnly.length > 0) {
        const ids = criticalOnly.map((c) => c.cve_id).join(", ");
        parts.push(
          `${ids} — CRITICAL severity, no public exploit confirmed yet but patching is urgent.`,
        );
      }

      if (exploitOnly.length > 0) {
        const ids = exploitOnly.map((c) => c.cve_id).join(", ");
        const sevs = exploitOnly
          .map((c) => c.detail?.cvss_severity ?? "UNKNOWN")
          .join(", ");
        parts.push(
          `${ids} (${sevs}) — public exploit available, severity below CRITICAL but exploitation risk is real.`,
        );
      }

      cveDetail = " Detected CVEs: " + parts.join(" | ");
    }

    finalAssessment =
      `Overall Assessment: CRITICAL RISK — Weighted confidence score ${weightedScore}/100 confirms high malicious likelihood.` +
      cveDetail;
  } else if (classification.risk === "MEDIUM" || cveMatches.length > 0) {
    finalAssessment =
      `Overall Assessment: HIGH RISK — Weighted confidence score ${weightedScore}/100 indicates partial threat signal.` +
      (cveMatches.length > 0
        ? ` ${cveMatches.length} CVE(s) linked — patching and monitoring recommended.`
        : " Further monitoring and defensive action recommended.");
  } else {
    finalAssessment =
      `Overall Assessment: LOW RISK — Weighted confidence score ${weightedScore}/100 shows limited threat evidence.` +
      (cveMatches.length > 0
        ? " Note: CVE(s) detected but without strong exploitation evidence."
        : " Continued observation is advised.");
  }

  insights.push(finalAssessment);

  return insights.join("\n\n");
}
