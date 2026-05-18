import { randomUUID } from "crypto";

function isoNow() {
  return new Date().toISOString();
}

function stixId(type: string) {
  return `${type}--${randomUUID()}`;
}

function cleanString(value: any, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function getIndicatorPattern(type: string, indicator: string) {
  const t = cleanString(type).toLowerCase();
  const value = cleanString(indicator).replace(/'/g, "\\'");

  if (t === "ip" || t === "ipv4" || t === "ipv4-addr") {
    return `[ipv4-addr:value = '${value}']`;
  }

  if (t === "ipv6" || t === "ipv6-addr") {
    return `[ipv6-addr:value = '${value}']`;
  }

  if (t === "domain" || t === "domain-name") {
    return `[domain-name:value = '${value}']`;
  }

  if (t === "url") {
    return `[url:value = '${value}']`;
  }

  if (t === "sha256" || t === "hash-sha256" || t === "hash" || t === "file") {
    return `[file:hashes.'SHA-256' = '${value}']`;
  }

  if (t === "sha1" || t === "hash-sha1") {
    return `[file:hashes.'SHA-1' = '${value}']`;
  }

  if (t === "md5" || t === "hash-md5") {
    return `[file:hashes.MD5 = '${value}']`;
  }

  return `[artifact:payload_bin MATCHES '${value}']`;
}

function getObservableObject(type: string, indicator: string, created: string) {
  const t = cleanString(type).toLowerCase();
  const value = cleanString(indicator);

  if (t === "ip" || t === "ipv4" || t === "ipv4-addr") {
    return {
      type: "ipv4-addr",
      spec_version: "2.1",
      id: stixId("ipv4-addr"),
      value,
    };
  }

  if (t === "ipv6" || t === "ipv6-addr") {
    return {
      type: "ipv6-addr",
      spec_version: "2.1",
      id: stixId("ipv6-addr"),
      value,
    };
  }

  if (t === "domain" || t === "domain-name") {
    return {
      type: "domain-name",
      spec_version: "2.1",
      id: stixId("domain-name"),
      value,
    };
  }

  if (t === "url") {
    return {
      type: "url",
      spec_version: "2.1",
      id: stixId("url"),
      value,
    };
  }

  if (t === "sha256" || t === "hash-sha256" || t === "hash" || t === "file") {
    return {
      type: "file",
      spec_version: "2.1",
      id: stixId("file"),
      hashes: {
        "SHA-256": value,
      },
    };
  }

  if (t === "sha1" || t === "hash-sha1") {
    return {
      type: "file",
      spec_version: "2.1",
      id: stixId("file"),
      hashes: {
        "SHA-1": value,
      },
    };
  }

  if (t === "md5" || t === "hash-md5") {
    return {
      type: "file",
      spec_version: "2.1",
      id: stixId("file"),
      hashes: {
        MD5: value,
      },
    };
  }

  return null;
}
export function generateOpenCTISTIX21(data: any) {
  const created = isoNow();

  const {
    reportId,
    indicator,
    type,
    malicious = 0,
    suspicious = 0,
    harmless = 0,
    undetected = 0,
    totalVendors = 0,
    abuseScore = 0,
    totalReports = 0,
    abuseipdb = null,
    mispData = {},
    cveMatches = [],
    cveRiskScore = null,
    mitreData = null,
    whoisData = null,
    history = null,
    pe_header = null,
    correlationInsights = "",
  } = data;

  if (!indicator || !type) {
    throw new Error("indicator and type are required to export STIX 2.1");
  }

  const objects: any[] = [];
  const objectRefs: string[] = [];

  const identityId = stixId("identity");
  const reportStixId = stixId("report");
  const indicatorId = stixId("indicator");
  const observedDataId = stixId("observed-data");

  const confidence = Math.min(
    100,
    Math.round(
      malicious * 10 +
        suspicious * 5 +
        abuseScore * 0.4 +
        (mispData?.matchCount || 0) * 10,
    ),
  );

  const threatLevel =
    confidence >= 70 ? "high" : confidence >= 40 ? "medium" : "low";

  const identityObject = {
    type: "identity",
    spec_version: "2.1",
    id: identityId,
    created,
    modified: created,
    name: "Cyber Fusion",
    identity_class: "organization",
  };

  objects.push(identityObject);
  objectRefs.push(identityId);

  const indicatorObject = {
    type: "indicator",
    spec_version: "2.1",
    id: indicatorId,
    created,
    modified: created,
    created_by_ref: identityId,
    name: `${cleanString(type).toUpperCase()} Indicator - ${cleanString(indicator)}`,
    description:
      correlationInsights ||
      `Indicator generated from VirusTotal, AbuseIPDB, MISP, NVD, MITRE ATT&CK, and WHOIS enrichment.`,
    indicator_types: ["malicious-activity"],
    pattern: getIndicatorPattern(type, indicator),
    pattern_type: "stix",
    valid_from: created,
    confidence,
    labels: ["malicious-activity", threatLevel],
    external_references: [
      {
        source_name: "VirusTotal",
        description: `Malicious: ${malicious}, Suspicious: ${suspicious}, Harmless: ${harmless}, Undetected: ${undetected}, Total Vendors: ${totalVendors}`,
      },
      {
        source_name: "AbuseIPDB",
        description: `Abuse Score: ${abuseScore}, Total Reports: ${totalReports}`,
      },
      {
        source_name: "MISP",
        description: `Matched Events: ${mispData?.matchCount || 0}`,
      },
    ],
    x_opencti_score: confidence,
    x_cti_detection: {
      malicious,
      suspicious,
      harmless,
      undetected,
      total_vendors: totalVendors,
    },
  };

  objects.push(indicatorObject);
  objectRefs.push(indicatorId);

  const observable = getObservableObject(type, indicator, created);

  if (observable) {
    objects.push(observable);
    objectRefs.push(observable.id);

    objects.push({
      type: "observed-data",
      spec_version: "2.1",
      id: observedDataId,
      created,
      modified: created,
      created_by_ref: identityId,
      first_observed: created,
      last_observed: created,
      number_observed: 1,
      object_refs: [observable.id],
      x_cti_whois: whoisData,
      x_cti_history: history,
      x_cti_pe_header: pe_header,
      x_cti_abuseipdb: abuseipdb,
    });

    objectRefs.push(observedDataId);
  }

  if (mispData?.threatActor && mispData.threatActor !== "Unknown") {
    const threatActorId = stixId("threat-actor");

    objects.push({
      type: "threat-actor",
      spec_version: "2.1",
      id: threatActorId,
      created,
      modified: created,
      created_by_ref: identityId,
      name: cleanString(mispData.threatActor),
      threat_actor_types: ["unknown"],
      description: "Threat actor derived from MISP correlation.",
      confidence: 70,
      labels: ["misp-correlated"],
      x_cti_misp: mispData,
    });

    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: stixId("relationship"),
      created,
      modified: created,
      relationship_type: "indicates",
      source_ref: indicatorId,
      target_ref: threatActorId,
    });

    objectRefs.push(threatActorId);
  }

  if (Array.isArray(mitreData?.techniques)) {
    for (const technique of mitreData.techniques) {
      const attackPatternId = stixId("attack-pattern");

      objects.push({
        type: "attack-pattern",
        spec_version: "2.1",
        id: attackPatternId,
        created,
        modified: created,
        created_by_ref: identityId,
        name: cleanString(
          technique.techniqueName,
          cleanString(technique.technique, "Unknown Technique"),
        ),
        description:
          Array.isArray(technique.reasons) && technique.reasons.length > 0
            ? technique.reasons.join(" ")
            : "MITRE ATT&CK technique correlated from analysis.",
        external_references: [
          {
            source_name: "mitre-attack",
            external_id: cleanString(technique.technique),
          },
        ],
        confidence: Number(technique.confidence || 50),
      });

      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: stixId("relationship"),
        created,
        modified: created,
        relationship_type: "indicates",
        source_ref: indicatorId,
        target_ref: attackPatternId,
      });

      objectRefs.push(attackPatternId);
    }
  }

  if (Array.isArray(cveMatches)) {
    for (const cve of cveMatches) {
      const cveId = cleanString(cve.cve_id, "");
      if (!cveId) continue;

      const vulnerabilityId = stixId("vulnerability");

      objects.push({
        type: "vulnerability",
        spec_version: "2.1",
        id: vulnerabilityId,
        created,
        modified: created,
        created_by_ref: identityId,
        name: cveId,
        description:
          cve.detail?.description ||
          `Vulnerability correlated with indicator ${indicator}.`,
        external_references: [
          {
            source_name: "nvd",
            external_id: cveId,
          },
        ],
        x_cti_cvss_score: cve.detail?.cvss_score ?? null,
        x_cti_cvss_severity: cve.detail?.cvss_severity ?? null,
        x_cti_exploit_available: cve.detail?.exploit_available ?? false,
      });

      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: stixId("relationship"),
        created,
        modified: created,
        relationship_type: "related-to",
        source_ref: indicatorId,
        target_ref: vulnerabilityId,
      });

      objectRefs.push(vulnerabilityId);
    }
  }

  if (Array.isArray(mitreData?.mitigations)) {
    for (const mitigation of mitreData.mitigations) {
      const courseOfActionId = stixId("course-of-action");

      objects.push({
        type: "course-of-action",
        spec_version: "2.1",
        id: courseOfActionId,
        created,
        modified: created,
        created_by_ref: identityId,
        name: cleanString(mitigation.name, "Recommended Mitigation"),
        description: cleanString(mitigation.description),
        external_references: [
          {
            source_name: cleanString(mitigation.framework, "MITRE ATT&CK"),
            external_id: cleanString(mitigation.id),
          },
        ],
      });

      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: stixId("relationship"),
        created,
        modified: created,
        relationship_type: "mitigates",
        source_ref: courseOfActionId,
        target_ref: indicatorId,
      });

      objectRefs.push(courseOfActionId);
    }
  }

  const reportObject = {
    type: "report",
    spec_version: "2.1",
    id: reportStixId,
    created,
    modified: created,
    created_by_ref: identityId,
    name: `Threat Intelligence Report - ${cleanString(reportId, indicator)}`,
    description:
      correlationInsights ||
      `OpenCTI-compatible STIX 2.1 report for ${indicator}.`,
    published: created,
    report_types: ["threat-report"],
    labels: ["cti-report", threatLevel],
    object_refs: [...new Set(objectRefs)],
    external_references: [
      { source_name: "VirusTotal" },
      { source_name: "AbuseIPDB" },
      { source_name: "MISP" },
      { source_name: "NVD" },
      { source_name: "MITRE ATT&CK" },
      { source_name: "WHOIS" },
    ],
    x_cti_report_id: reportId || null,
    x_cti_cve_risk_score: cveRiskScore,
  };

  objects.push(reportObject);

  return {
    type: "bundle",
    id: stixId("bundle"),
    objects,
  };
}
