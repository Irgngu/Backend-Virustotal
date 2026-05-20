import { Hono } from "hono";

const nvd = new Hono();

type AffectedVersion = {
  vendor: string;
  product: string;
  version: string;
  criteria: string;
  versionStartIncluding: string | null;
  versionEndIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndExcluding: string | null;
};

type RemediationInfo = {
  source: string;
  url: string;
  tags: string[];
};

function parseAffectedVersions(configurations: any[] = []): AffectedVersion[] {
  const affectedVersions: AffectedVersion[] = [];

  configurations.forEach((config: any) => {
    (config.nodes || []).forEach((node: any) => {
      (node.cpeMatch || []).forEach((cpe: any) => {
        if (!cpe.vulnerable || !cpe.criteria) return;

        const parts = cpe.criteria.split(":");

        affectedVersions.push({
          vendor: parts[3] || "-",
          product: parts[4] || "-",
          version: parts[5] || "-",
          criteria: cpe.criteria,
          versionStartIncluding: cpe.versionStartIncluding ?? null,
          versionEndIncluding: cpe.versionEndIncluding ?? null,
          versionStartExcluding: cpe.versionStartExcluding ?? null,
          versionEndExcluding: cpe.versionEndExcluding ?? null,
        });
      });
    });
  });

  return affectedVersions;
}

function parseRemediation(references: any[] = []): RemediationInfo[] {
  return references
    .filter((ref: any) => {
      const tags: string[] = ref.tags || [];

      return (
        tags.includes("Patch") ||
        tags.includes("Vendor Advisory") ||
        tags.includes("Release Notes") ||
        tags.includes("Mitigation")
      );
    })
    .map((ref: any) => ({
      source: ref.source || "Unknown",
      url: ref.url || "-",
      tags: ref.tags || [],
    }));
}

function parseNVDResult(data: any) {
  return (data.vulnerabilities || []).map((item: any) => {
    const cve = item.cve;

    const cvssV3 =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
      cve.metrics?.cvssMetricV30?.[0]?.cvssData ||
      null;

    const references = cve.references || [];
    const remediation = parseRemediation(references);

    return {
      cve_id: cve.id,

      description:
        cve.descriptions?.find((d: any) => d.lang === "en")?.value ||
        "No description available",

      cvss_score: cvssV3?.baseScore ?? null,
      cvss_severity: cvssV3?.baseSeverity ?? null,
      cvss_vector: cvssV3?.vectorString ?? null,

      affected_versions: parseAffectedVersions(cve.configurations || []),

      remediation,
      patch_available: remediation.length > 0,

      published_date: cve.published ?? null,
      last_modified: cve.lastModified ?? null,
    };
  });
}

nvd.get("/", async (c) => {
  try {
    const keyword = c.req.query("keyword");

    if (!keyword) {
      return c.json({ error: "keyword query is required" }, 400);
    }

    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?keywordSearch=${encodeURIComponent(keyword)}` +
      `&resultsPerPage=5`;

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (process.env.NVD_API_KEY) {
      headers.apiKey = process.env.NVD_API_KEY;
    }

    const response = await fetch(url, { headers });

    if (!response.ok) {
      return c.json(
        {
          error: "Failed fetch NVD data",
          status: response.status,
          details: await response.text(),
        },
        500,
      );
    }

    const data = await response.json();

    return c.json({
      keyword,
      totalResults: data.totalResults ?? 0,
      results: parseNVDResult(data),
    });
  } catch (error: any) {
    return c.json(
      {
        error: "Failed fetch NVD data",
        details: error.message,
      },
      500,
    );
  }
});

export default nvd;