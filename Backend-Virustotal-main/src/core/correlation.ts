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

  // --- AbuseIPDB ---
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

  // --- MISP ---
  if ((mispData.matchCount || 0) > 0) {
    insights.push(
      `Threat intelligence correlation: ${mispData.matchCount} matching event(s) found in MISP, linking this indicator to known campaigns.`,
    );
  } else {
    insights.push(
      `No threat intelligence correlation: 0 matches found in MISP, indicating no known association with tracked campaigns.`,
    );
  }

  // --- FINAL SUMMARY ---
  let finalAssessment = "";

  if (vtRatio > 0.3 && abuseScore > 50) {
    finalAssessment =
      "Overall Assessment: HIGH RISK — Strong multi-source correlation confirms this indicator is actively malicious.";
  } else if (
    vtRatio > 0.1 ||
    abuseScore > 40 ||
    (mispData.matchCount || 0) > 0
  ) {
    finalAssessment =
      "Overall Assessment: MEDIUM RISK — Partial correlation detected. Further monitoring and defensive action recommended.";
  } else {
    finalAssessment =
      "Overall Assessment: LOW RISK — Limited evidence of malicious activity, but continued observation is advised.";
  }

  insights.push(finalAssessment);

  return insights.join("\n\n");
}

// type MISPData = {
//   matchCount?: number;
// };

// type CorrelationInput = {
//   malicious: number;
//   totalVendors: number;
//   abuseScore: number;
//   totalReports: number;
//   mispData: MISPData;
//   nvdData?: any;
//   censysData?: any;
// };

// export function generateCorrelationInsights({
//   malicious,
//   totalVendors,
//   abuseScore,
//   totalReports,
//   mispData,
//   nvdData,
//   censysData,
// }: CorrelationInput): string {
//   const insights: string[] = [];

//   const vtRatio = malicious / Math.max(totalVendors, 1);

//   if (vtRatio > 0.3) {
//     insights.push(
//       `High confidence malicious detection: ${malicious}/${totalVendors} vendors flagged this indicator.`,
//     );
//   } else if (vtRatio > 0.1) {
//     insights.push(`Moderate malicious detection observed.`);
//   } else {
//     insights.push(`Low detection ratio observed.`);
//   }

//   if (abuseScore > 70) {
//     insights.push(`High abuse confidence from AbuseIPDB.`);
//   } else if (abuseScore > 30) {
//     insights.push(`Moderate abuse reputation detected.`);
//   }

//   const mispMatches = mispData?.matchCount || 0;

//   if (mispMatches > 0) {
//     insights.push(`MISP correlation found ${mispMatches} related events.`);
//   }

//   const vulnerabilities = nvdData?.vulnerabilities || [];
//   const cveCount = vulnerabilities.length;

//   if (cveCount > 0) {
//     insights.push(`NVD returned ${cveCount} related CVE records.`);
//   }

//   /* ===============================
//      CENSYS
//   ============================== */
//   const services = censysData?.services || [];

//   if (services.length > 0) {
//     insights.push(
//       `Censys detected ${services.length} exposed network services, increasing external attack surface.`,
//     );
//   }

//   let riskScore = 0;

//   if (vtRatio > 0.3) riskScore += 40;
//   else if (vtRatio > 0.1) riskScore += 20;

//   if (abuseScore > 70) riskScore += 20;
//   if (mispMatches > 0) riskScore += 15;
//   if (cveCount > 0) riskScore += 15;
//   if (services.length >= 5) riskScore += 15;

//   if (riskScore >= 70) {
//     insights.push("Overall Assessment: HIGH RISK");
//   } else if (riskScore >= 40) {
//     insights.push("Overall Assessment: MEDIUM RISK");
//   } else {
//     insights.push("Overall Assessment: LOW RISK");
//   }

//   return insights.join("\n\n");
// }

// export function extractProducts(data: any) {
//   const results: any[] = [];

//   const services = data?.services || [];

//   for (const svc of services) {
//     const software = svc?.software || [];

//     for (const sw of software) {
//       results.push({
//         vendor: sw.vendor || "Unknown",
//         product: sw.product || "Unknown",
//         version: sw.version || "",
//         port: svc.port || null,
//       });
//     }
//   }

//   return results;
// }
