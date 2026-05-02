// src/services/cve.ts
// CVE Matching Engine — ekstraksi dari VT, AbuseIPDB, MISP + enrichment NVD

// ══════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════

export interface CVEMetrics {
  attack_vector: string | null;
  attack_complexity: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  scope: string | null;
  confidentiality_impact: string | null;
  integrity_impact: string | null;
  availability_impact: string | null;
}

export interface CVEDetail {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  cvss_vector: string | null;
  cvss_metrics: CVEMetrics;
  cwe: string[];
  affected_products: string[];
  patch_available: boolean;
  patch_id: string | null;
  exploit_available: boolean;
  published_date: string | null;
  last_modified: string | null;
}

export interface CVEMatchResult {
  cve_id: string;
  source: string; // dari mana CVE ini terdeteksi
  confidence: "HIGH" | "MEDIUM" | "LOW";
  detail: CVEDetail | null;
}

export interface CVERiskScore {
  score: number; // 0-100 composite
  highest_cvss: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  exploit_count: number;
}

// ══════════════════════════════════════════════════════
// REGEX EXTRACTOR
// ══════════════════════════════════════════════════════

export function extractCVEByRegex(text: string): string[] {
  if (!text) return [];
  const pattern = /CVE-\d{4}-\d{4,7}/gi;
  const matches = text.match(pattern) || [];
  return [...new Set(matches.map((c) => c.toUpperCase()))];
}

// ══════════════════════════════════════════════════════
// EKSTRAK CVE DARI VIRUSTOTAL
// Sesuai dengan struktur virustotal.ts yang sudah diperbarui
// ══════════════════════════════════════════════════════

export function extractCVEFromVT(vtResult: any): string[] {
  const cveList: string[] = [];

  if (!vtResult) return cveList;

  // 1. Dari cve_extracted yang sudah diparse di virustotal.ts
  const cveExtracted: string[] = vtResult?.virustotal?.cve_extracted || [];
  cveList.push(...cveExtracted);

  // 2. Dari tags VT langsung
  const tags: string[] = vtResult?.virustotal?.tags || [];
  tags.forEach((tag: string) => {
    if (/^CVE-\d{4}-\d{4,7}$/i.test(tag)) {
      cveList.push(tag.toUpperCase());
    }
  });

  // 3. Dari crowdsourced_context yang sudah diparse
  const crowdsourcedCtx = vtResult?.virustotal?.crowdsourced_context || [];
  crowdsourcedCtx.forEach((ctx: any) => {
    const found = ctx.cve || [];
    cveList.push(...found.map((c: string) => c.toUpperCase()));
  });

  // 4. Dari sigma_analysis_results
  const sigmaResults = vtResult?.virustotal?.sigma_analysis_results || [];
  sigmaResults.forEach((sigma: any) => {
    const found = extractCVEByRegex(sigma.rule_title || "");
    cveList.push(...found);
  });

  // 5. Dari vendor results (scan result strings)
  const vendors = vtResult?.vendors || [];
  vendors.forEach((vendor: any) => {
    const found = extractCVEByRegex(vendor.result || "");
    cveList.push(...found);
  });

  return [...new Set(cveList)];
}

// ══════════════════════════════════════════════════════
// EKSTRAK CVE DARI ABUSEIPDB
// Sesuai dengan struktur abuseipdb.ts yang sudah diperbarui
// recent_reports[].comment bisa mengandung CVE mention
// ══════════════════════════════════════════════════════

export function extractCVEFromAbuse(abuseipdb: any): string[] {
  const cveList: string[] = [];

  if (!abuseipdb) return cveList;

  // Dari recent_reports comments
  const reports = abuseipdb?.recent_reports || [];
  reports.forEach((report: any) => {
    const found = extractCVEByRegex(report.comment || "");
    cveList.push(...found);
  });

  return [...new Set(cveList)];
}

// ══════════════════════════════════════════════════════
// EKSTRAK CVE DARI MISP
// Sesuai dengan struktur misp.ts
// tags bisa berisi "CVE-XXXX-XXXXX"
// ══════════════════════════════════════════════════════

export function extractCVEFromMISP(mispData: any): string[] {
  const cveList: string[] = [];

  if (!mispData) return cveList;

  // Dari tags MISP
  const tags: string[] = mispData?.tags || [];
  tags.forEach((tag: string) => {
    const found = extractCVEByRegex(tag);
    cveList.push(...found);
  });

  // Dari campaigns (tags non-TLP)
  const campaigns: string[] = mispData?.campaigns || [];
  campaigns.forEach((tag: string) => {
    const found = extractCVEByRegex(tag);
    cveList.push(...found);
  });

  // Dari title event MISP
  const title = mispData?.title || "";
  const foundInTitle = extractCVEByRegex(title);
  cveList.push(...foundInTitle);

  return [...new Set(cveList)];
}

// ══════════════════════════════════════════════════════
// NVD API — Ambil detail lengkap per CVE
// ══════════════════════════════════════════════════════

export async function fetchCVEFromNVD(
  cveId: string,
): Promise<CVEDetail | null> {
  try {
    const NVD_API_KEY = process.env.NVD_API_KEY;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (NVD_API_KEY) {
      headers["apiKey"] = NVD_API_KEY;
    }

    // Rate limit: NVD free = 5 req/30s, with key = 50 req/30s
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { headers },
    );

    if (!res.ok) {
      console.warn(`[NVD] ${cveId} → HTTP ${res.status}`);
      return null;
    }

    const data = await res.json();
    const vuln = data?.vulnerabilities?.[0]?.cve;

    if (!vuln) return null;

    // Ambil CVSS v3.1, fallback v3.0, fallback v2
    const cvssV3 =
      vuln.metrics?.cvssMetricV31?.[0]?.cvssData ||
      vuln.metrics?.cvssMetricV30?.[0]?.cvssData ||
      null;

    // CWE list
    const cweList: string[] = (vuln.weaknesses || [])
      .flatMap((w: any) =>
        (w.description || [])
          .filter((d: any) => d.lang === "en")
          .map((d: any) => d.value as string),
      )
      .filter(Boolean);

    // Affected products dari CPE
    const affectedProducts: string[] = [];
    (vuln.configurations || []).forEach((config: any) => {
      (config.nodes || []).forEach((node: any) => {
        (node.cpeMatch || []).forEach((cpe: any) => {
          if (cpe.vulnerable && cpe.criteria) {
            const parts = cpe.criteria.split(":");
            if (parts.length >= 5) {
              const productStr = [
                parts[3],
                parts[4],
                parts[5] !== "*" ? parts[5] : "",
              ]
                .filter(Boolean)
                .join(" ")
                .trim();
              if (productStr) affectedProducts.push(productStr);
            }
          }
        });
      });
    });

    // Patch & exploit dari references
    const references = vuln.references || [];
    const hasPatch = references.some(
      (ref: any) =>
        ref.tags?.includes("Patch") || ref.tags?.includes("Vendor Advisory"),
    );
    const hasExploit = references.some(
      (ref: any) =>
        ref.tags?.includes("Exploit") ||
        (ref.url || "").includes("exploit-db") ||
        (ref.url || "").includes("poc") ||
        (ref.url || "").includes("github.com/exploit"),
    );

    return {
      cve_id: cveId,
      description:
        vuln.descriptions?.find((d: any) => d.lang === "en")?.value ||
        "No description available",
      cvss_score: cvssV3?.baseScore ?? null,
      cvss_severity: cvssV3?.baseSeverity ?? null,
      cvss_vector: cvssV3?.vectorString ?? null,
      cvss_metrics: {
        attack_vector: cvssV3?.attackVector ?? null,
        attack_complexity: cvssV3?.attackComplexity ?? null,
        privileges_required: cvssV3?.privilegesRequired ?? null,
        user_interaction: cvssV3?.userInteraction ?? null,
        scope: cvssV3?.scope ?? null,
        confidentiality_impact: cvssV3?.confidentialityImpact ?? null,
        integrity_impact: cvssV3?.integrityImpact ?? null,
        availability_impact: cvssV3?.availabilityImpact ?? null,
      },
      cwe: [...new Set(cweList)],
      affected_products: [...new Set(affectedProducts)].slice(0, 8),
      patch_available: hasPatch,
      patch_id: null,
      exploit_available: hasExploit,
      published_date: vuln.published ?? null,
      last_modified: vuln.lastModified ?? null,
    };
  } catch (err) {
    console.error(`[NVD] Failed to fetch ${cveId}:`, err);
    return null;
  }
}

// ══════════════════════════════════════════════════════
// MASTER FUNCTION: Jalankan semua sumber → enrich NVD
// ══════════════════════════════════════════════════════

export async function matchCVE(params: {
  vtResult?: any;
  abuseipdb?: any;
  mispData?: any;
}): Promise<CVEMatchResult[]> {
  const cveMap = new Map<string, CVEMatchResult>();

  // Kumpulkan dari semua sumber
  const fromVT = extractCVEFromVT(params.vtResult);
  const fromAbuse = extractCVEFromAbuse(params.abuseipdb);
  const fromMISP = extractCVEFromMISP(params.mispData);

  // VT → confidence HIGH (langsung dari vendor tags)
  fromVT.forEach((cve) => {
    cveMap.set(cve, {
      cve_id: cve,
      source: "VirusTotal",
      confidence: "HIGH",
      detail: null,
    });
  });

  // AbuseIPDB → confidence MEDIUM (dari comment report)
  fromAbuse.forEach((cve) => {
    if (!cveMap.has(cve)) {
      cveMap.set(cve, {
        cve_id: cve,
        source: "AbuseIPDB",
        confidence: "MEDIUM",
        detail: null,
      });
    } else {
      const existing = cveMap.get(cve)!;
      existing.source += " + AbuseIPDB";
    }
  });

  // MISP → confidence HIGH (komunitas terverifikasi)
  fromMISP.forEach((cve) => {
    if (!cveMap.has(cve)) {
      cveMap.set(cve, {
        cve_id: cve,
        source: "MISP",
        confidence: "HIGH",
        detail: null,
      });
    } else {
      const existing = cveMap.get(cve)!;
      existing.source += " + MISP";
      existing.confidence = "HIGH"; // multi-source = HIGH
    }
  });

  if (cveMap.size === 0) return [];

  // Enrich dengan NVD — parallel, max 5 CVE (rate limit NVD)
  const cveList = [...cveMap.values()].slice(0, 5);

  const enriched = await Promise.allSettled(
    cveList.map(async (item) => {
      const detail = await fetchCVEFromNVD(item.cve_id);
      return { ...item, detail };
    }),
  );

  const results: CVEMatchResult[] = enriched
    .filter((r) => r.status === "fulfilled")
    .map((r) => (r as PromiseFulfilledResult<CVEMatchResult>).value);

  // Sort: CVSS tertinggi dulu, lalu alphabetical
  results.sort((a, b) => {
    const scoreA = a.detail?.cvss_score ?? 0;
    const scoreB = b.detail?.cvss_score ?? 0;
    if (scoreB !== scoreA) return scoreB - scoreA;
    return a.cve_id.localeCompare(b.cve_id);
  });

  return results;
}

// ══════════════════════════════════════════════════════
// COMPOSITE CVE RISK SCORE
// ══════════════════════════════════════════════════════

export function calculateCVERiskScore(
  cveResults: CVEMatchResult[],
): CVERiskScore {
  if (!cveResults.length) {
    return {
      score: 0,
      highest_cvss: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      exploit_count: 0,
    };
  }

  const cvssScores = cveResults
    .map((c) => c.detail?.cvss_score ?? 0)
    .filter((s) => s > 0);

  const highest_cvss = Math.max(...cvssScores, 0);
  const critical_count = cveResults.filter(
    (c) => c.detail?.cvss_severity === "CRITICAL",
  ).length;
  const high_count = cveResults.filter(
    (c) => c.detail?.cvss_severity === "HIGH",
  ).length;
  const medium_count = cveResults.filter(
    (c) => c.detail?.cvss_severity === "MEDIUM",
  ).length;
  const exploit_count = cveResults.filter(
    (c) => c.detail?.exploit_available === true,
  ).length;

  // Composite score (0-100)
  const score = Math.min(
    100,
    (highest_cvss / 10) * 50 + // CVSS weight 50%
      critical_count * 15 + // Critical bonus 15 per CVE
      high_count * 8 + // High bonus 8 per CVE
      exploit_count * 12, // Exploit bonus 12 per CVE
  );

  return {
    score: Math.round(score),
    highest_cvss,
    critical_count,
    high_count,
    medium_count,
    exploit_count,
  };
}
