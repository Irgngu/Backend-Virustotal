type MISPData = {
  matchCount?: number;
};

type CorrelationInput = {
  malicious: number;
  totalVendors: number;
  abuseScore: number;
  totalReports: number;
  mispData: MISPData;
};

export function generateCorrelationInsights({
  malicious,
  totalVendors,
  abuseScore,
  totalReports,
  mispData,
}: CorrelationInput): string {
  let insights: string[] = [];

  const vtRatio = malicious / Math.max(totalVendors, 1);

  // --- VirusTotal ---
  if (vtRatio > 0.3) {
    insights.push(
      `High confidence malicious detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%).`
    );
  } else if (vtRatio > 0.1) {
    insights.push(
      `Moderate detection: ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), suggesting a potentially emerging or evasive threat.`
    );
  } else {
    insights.push(
      `Low detection: Only ${malicious}/${totalVendors} vendors flagged this indicator (${(vtRatio * 100).toFixed(1)}%), indicating low visibility or a new threat.`
    );
  }

  // --- AbuseIPDB ---
  if (abuseScore > 70) {
    insights.push(
      `High abuse confidence: Score ${abuseScore}% with ${totalReports} reports, indicating active malicious usage in real-world environments.`
    );
  } else if (abuseScore > 30) {
    insights.push(
      `Moderate abuse activity: Score ${abuseScore}% with ${totalReports} reports, suggesting suspicious but not fully confirmed malicious behavior.`
    );
  } else {
    insights.push(
      `Low abuse activity: Score ${abuseScore}% with ${totalReports} reports, indicating limited or no widespread abuse.`
    );
  }

  // --- MISP ---
  if ((mispData.matchCount || 0) > 0) {
    insights.push(
      `Threat intelligence correlation: ${mispData.matchCount} matching event(s) found in MISP, linking this indicator to known campaigns.`
    );
  } else {
    insights.push(
      `No threat intelligence correlation: 0 matches found in MISP, indicating no known association with tracked campaigns.`
    );
  }

  // --- FINAL SUMMARY ---
  let finalAssessment = "";

  if (vtRatio > 0.3 && abuseScore > 50) {
    finalAssessment =
      "Overall Assessment: HIGH RISK — Strong multi-source correlation confirms this indicator is actively malicious.";
  } else if (vtRatio > 0.1 || abuseScore > 40 || (mispData.matchCount || 0) > 0) {
    finalAssessment =
      "Overall Assessment: MEDIUM RISK — Partial correlation detected. Further monitoring and defensive action recommended.";
  } else {
    finalAssessment =
      "Overall Assessment: LOW RISK — Limited evidence of malicious activity, but continued observation is advised.";
  }

  insights.push(finalAssessment);

  return insights.join("\n\n");
}