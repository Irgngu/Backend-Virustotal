import { randomUUID, createHash } from "crypto";

type StixExternalReference = {
  source_name: string;
  description?: string;
  external_id?: string;
  url?: string;
};

/**
 * STIX 2.1 namespace for deterministic UUIDv5 cyber observable IDs.
 */
const STIX_SCO_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

function isoNow() {
  return new Date().toISOString();
}

function stixId(type: string) {
  return `${type}--${randomUUID()}`;
}

function cleanString(value: any, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  const str = String(value).trim();
  return str === "" ? fallback : str;
}

function optionalString(value: any) {
  if (value === null || value === undefined || value === "") return undefined;
  const str = String(value).trim();
  if (str === "" || str === "-") return undefined;
  return str;
}

function toNumber(value: any, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clampScore(value: any, fallback = 0) {
  const n = toNumber(value, fallback);
  return Math.max(0, Math.min(100, Math.round(n)));
}

function escapeStixPatternValue(value: any) {
  return cleanString(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function makeExternalReference(
  sourceName: any,
  description?: any,
  externalId?: any,
  url?: any,
): StixExternalReference {
  const ref: StixExternalReference = {
    source_name: cleanString(sourceName, "Unknown Source"),
  };

  const desc = optionalString(description);
  const extId = optionalString(externalId);
  const link = optionalString(url);

  if (desc) ref.description = desc;
  if (extId) ref.external_id = extId;
  if (link) ref.url = link;

  if (!ref.description && !ref.external_id && !ref.url) {
    ref.description = `External reference source: ${ref.source_name}`;
  }

  return ref;
}

function uuidToBytes(uuid: string) {
  const hex = uuid.replace(/-/g, "");

  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error(`Invalid UUID namespace: ${uuid}`);
  }

  return Buffer.from(hex, "hex");
}

function bytesToUuid(bytes: Buffer) {
  const hex = bytes.toString("hex");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

function uuidv5(name: string, namespace: string) {
  const namespaceBytes = uuidToBytes(namespace);

  const hash = createHash("sha1")
    .update(namespaceBytes)
    .update(name, "utf8")
    .digest();

  const bytes = Buffer.from(hash.subarray(0, 16));

  if (bytes.length < 16) {
    throw new Error("Invalid SHA-1 hash length for UUIDv5 generation");
  }

  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  return bytesToUuid(bytes);
}

function canonicalJson(value: any): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  const keys = Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort();

  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function scoId(type: string, idContributingProperties: any) {
  const canonical = canonicalJson(idContributingProperties);
  return `${type}--${uuidv5(canonical, STIX_SCO_NAMESPACE)}`;
}

function extractScoreFromText(text: any) {
  const value = optionalString(text);
  if (!value) return undefined;

  const match = value.match(
    /(?:weighted\s+confidence\s+score|confidence\s+score|risk\s+score)\s*[:=]\s*(\d{1,3})\s*\/\s*100/i,
  );

  if (!match) return undefined;
  return clampScore(match[1]);
}

function detectThreatLevel(confidence: number, text: any) {
  const value = optionalString(text)?.toLowerCase() || "";

  if (value.includes("critical") || value.includes("high risk")) {
    return "high";
  }

  if (
    value.includes("medium") ||
    value.includes("suspicious") ||
    value.includes("moderate")
  ) {
    return "medium";
  }

  if (value.includes("low")) {
    return "low";
  }

  if (confidence >= 70) return "high";
  if (confidence >= 30) return "medium";
  return "low";
}

function extractCveId(value: any) {
  const str = optionalString(value);
  if (!str) return undefined;

  const match = str.match(/CVE-\d{4}-\d{4,}/i);
  if (!match) return undefined;

  return match[0].toUpperCase();
}

function detectHashAlgorithm(type: string, indicator: string) {
  const t = cleanString(type).toLowerCase();
  const value = cleanString(indicator);

  if (t === "sha256" || t === "hash-sha256") return "SHA-256";
  if (t === "sha1" || t === "hash-sha1") return "SHA-1";
  if (t === "md5" || t === "hash-md5") return "MD5";

  if (t === "hash" || t === "file") {
    if (/^[a-fA-F0-9]{64}$/.test(value)) return "SHA-256";
    if (/^[a-fA-F0-9]{40}$/.test(value)) return "SHA-1";
    if (/^[a-fA-F0-9]{32}$/.test(value)) return "MD5";
  }

  return null;
}

function getIndicatorPattern(type: string, indicator: string) {
  const t = cleanString(type).toLowerCase();
  const value = escapeStixPatternValue(indicator);
  const hashAlgorithm = detectHashAlgorithm(type, indicator);

  if (t === "ip" || t === "ipv4" || t === "ipv4-addr") {
    return `[ipv4-addr:value = '${value}']`;
  }

  if (t === "ipv6" || t === "ipv6-addr") {
    return `[ipv6-addr:value = '${value}']`;
  }

  if (t === "domain" || t === "domain-name" || t === "hostname") {
    return `[domain-name:value = '${value}']`;
  }

  if (t === "url") {
    return `[url:value = '${value}']`;
  }

  if (hashAlgorithm) {
    return `[file:hashes.'${hashAlgorithm}' = '${value}']`;
  }

  throw new Error(
    `Unsupported or invalid IOC type/hash format for STIX pattern: type=${type}, indicator=${indicator}`,
  );
}

function getObservableObject(type: string, indicator: string) {
  const t = cleanString(type).toLowerCase();
  const value = cleanString(indicator);
  const hashAlgorithm = detectHashAlgorithm(type, indicator);

  if (t === "ip" || t === "ipv4" || t === "ipv4-addr") {
    const idProps = { value };

    return {
      type: "ipv4-addr",
      spec_version: "2.1",
      id: scoId("ipv4-addr", idProps),
      value,
    };
  }

  if (t === "ipv6" || t === "ipv6-addr") {
    const idProps = { value };

    return {
      type: "ipv6-addr",
      spec_version: "2.1",
      id: scoId("ipv6-addr", idProps),
      value,
    };
  }

  if (t === "domain" || t === "domain-name" || t === "hostname") {
    const idProps = { value };

    return {
      type: "domain-name",
      spec_version: "2.1",
      id: scoId("domain-name", idProps),
      value,
    };
  }

  if (t === "url") {
    const idProps = { value };

    return {
      type: "url",
      spec_version: "2.1",
      id: scoId("url", idProps),
      value,
    };
  }

  if (hashAlgorithm) {
    const hashes = {
      [hashAlgorithm]: value,
    };

    const idProps = { hashes };

    return {
      type: "file",
      spec_version: "2.1",
      id: scoId("file", idProps),
      hashes,
    };
  }

  return null;
}

function buildDetectionSummary(data: {
  malicious: any;
  suspicious: any;
  harmless: any;
  undetected: any;
  totalVendors: any;
  abuseScore: any;
  totalReports: any;
  mispMatchCount: any;
  threatLevel: string;
  confidence: number;
}) {
  return [
    `Threat level: ${data.threatLevel.toUpperCase()}.`,
    `Confidence score: ${data.confidence}/100.`,
    `VirusTotal detection: malicious=${data.malicious}, suspicious=${data.suspicious}, harmless=${data.harmless}, undetected=${data.undetected}, total_vendors=${data.totalVendors}.`,
    `AbuseIPDB summary: abuse_score=${data.abuseScore}, total_reports=${data.totalReports}.`,
    `MISP correlation: matched_events=${data.mispMatchCount}.`,
  ].join(" ");
}

function buildObservedSummary(params: {
  whoisData: any;
  history: any;
  pe_header: any;
  abuseipdb: any;
}) {
  const parts: string[] = [];

  if (params.whoisData) {
    parts.push(`WHOIS/RDAP enrichment is available.`);
  }

  if (params.history) {
    parts.push(`Submission or observation history is available.`);
  }

  if (params.pe_header) {
    parts.push(`PE header metadata is available.`);
  }

  if (params.abuseipdb) {
    const score =
      params.abuseipdb.abuse_confidence_score ??
      params.abuseipdb.abuseConfidenceScore ??
      "-";

    const reports =
      params.abuseipdb.total_reports ?? params.abuseipdb.totalReports ?? "-";

    parts.push(
      `AbuseIPDB enrichment is available with abuse score ${score} and total reports ${reports}.`,
    );
  }

  if (parts.length === 0) {
    return "Observed data generated from the submitted indicator.";
  }

  return parts.join(" ");
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

  const pushObject = (obj: any, includeInReport = true) => {
    objects.push(obj);

    if (includeInReport && obj?.id) {
      objectRefs.push(obj.id);
    }

    return obj;
  };

  const pushRelationship = (
    relationshipType: string,
    sourceRef: string,
    targetRef: string,
  ) => {
    return pushObject({
      type: "relationship",
      spec_version: "2.1",
      id: stixId("relationship"),
      created,
      modified: created,
      relationship_type: relationshipType,
      source_ref: sourceRef,
      target_ref: targetRef,
    });
  };

  const computedConfidence = clampScore(
    toNumber(malicious) * 10 +
      toNumber(suspicious) * 5 +
      toNumber(abuseScore) * 0.4 +
      toNumber(mispData?.matchCount) * 10,
  );

  const extractedConfidence = extractScoreFromText(correlationInsights);
  const confidence = extractedConfidence ?? computedConfidence;
  const threatLevel = detectThreatLevel(confidence, correlationInsights);

  const detectionSummary = buildDetectionSummary({
    malicious,
    suspicious,
    harmless,
    undetected,
    totalVendors,
    abuseScore,
    totalReports,
    mispMatchCount: mispData?.matchCount || 0,
    threatLevel,
    confidence,
  });

  const identityObject = {
    type: "identity",
    spec_version: "2.1",
    id: identityId,
    created,
    modified: created,
    name: "Cyber Fusion",
    identity_class: "organization",
  };

  pushObject(identityObject);

  const indicatorObject = {
    type: "indicator",
    spec_version: "2.1",
    id: indicatorId,
    created,
    modified: created,
    created_by_ref: identityId,
    name: `${cleanString(type).toUpperCase()} Indicator - ${cleanString(indicator)}`,
    description: `${correlationInsights || "Indicator generated from threat intelligence enrichment."}\n\n${detectionSummary}`,
    indicator_types: ["malicious-activity"],
    pattern: getIndicatorPattern(type, indicator),
    pattern_type: "stix",
    valid_from: created,
    confidence,
    labels: ["malicious-activity", threatLevel],
    external_references: [
      makeExternalReference(
        "VirusTotal",
        `VirusTotal security vendor analysis. Malicious: ${malicious}, Suspicious: ${suspicious}, Harmless: ${harmless}, Undetected: ${undetected}, Total Vendors: ${totalVendors}.`,
      ),
      makeExternalReference(
        "AbuseIPDB",
        `AbuseIPDB IP reputation analysis. Abuse Score: ${abuseScore}, Total Reports: ${totalReports}.`,
      ),
      makeExternalReference(
        "MISP",
        `MISP threat intelligence correlation. Matched Events: ${mispData?.matchCount || 0}.`,
      ),
    ],
  };

  pushObject(indicatorObject);

  const observable = getObservableObject(type, indicator);

  if (observable) {
    pushObject(observable);

    const observedDataObject = {
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
      labels: ["observed-indicator"],
    };

    pushObject(observedDataObject);
  }

  if (mispData?.threatActor && mispData.threatActor !== "Unknown") {
    const threatActorId = stixId("threat-actor");

    const threatActorObject = {
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
      external_references: [
        makeExternalReference(
          "MISP",
          "Threat actor information derived from MISP correlation data.",
        ),
      ],
    };

    pushObject(threatActorObject);
    pushRelationship("indicates", indicatorId, threatActorId);
  }

  if (Array.isArray(mitreData?.techniques)) {
    for (const technique of mitreData.techniques) {
      const attackPatternId = stixId("attack-pattern");

      const techniqueId = optionalString(
        technique.technique || technique.id || technique.techniqueId,
      );

      const attackPatternObject = {
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
          makeExternalReference(
            "mitre-attack",
            "MITRE ATT&CK technique reference correlated from analysis.",
            techniqueId,
          ),
        ],
        confidence: clampScore(technique.confidence, 50),
      };

      pushObject(attackPatternObject);
      pushRelationship("indicates", indicatorId, attackPatternId);
    }
  }

  if (Array.isArray(cveMatches)) {
    for (const cve of cveMatches) {
      const cveId = extractCveId(
        cve.cve_id || cve.id || cve.cveId || cve?.cve?.id,
      );

      if (!cveId) continue;

      const vulnerabilityId = stixId("vulnerability");

      const cvssScore = cve.detail?.cvss_score ?? cve.cvss_score ?? "N/A";
      const cvssSeverity =
        cve.detail?.cvss_severity ?? cve.cvss_severity ?? "UNKNOWN";

      const exploitAvailable =
        cve.detail?.exploit_available ?? cve.exploit_available ?? false;

      const vulnerabilityObject = {
        type: "vulnerability",
        spec_version: "2.1",
        id: vulnerabilityId,
        created,
        modified: created,
        created_by_ref: identityId,
        name: cveId,
        description:
          cve.detail?.description ||
          cve.description ||
          `Vulnerability correlated with indicator ${indicator}. CVSS score: ${cvssScore}. Severity: ${cvssSeverity}. Exploit available: ${exploitAvailable}.`,
        external_references: [
          {
            source_name: "cve",
            external_id: cveId,
          },
        ],
      };

      pushObject(vulnerabilityObject);
      pushRelationship("related-to", indicatorId, vulnerabilityId);
    }
  }

  if (Array.isArray(mitreData?.mitigations)) {
    for (const mitigation of mitreData.mitigations) {
      const courseOfActionId = stixId("course-of-action");

      const mitigationName = cleanString(
        mitigation.name,
        "Recommended Mitigation",
      );

      const mitigationDescription = cleanString(
        mitigation.description,
        "Recommended mitigation action derived from threat intelligence analysis.",
      );

      const courseOfActionObject = {
        type: "course-of-action",
        spec_version: "2.1",
        id: courseOfActionId,
        created,
        modified: created,
        created_by_ref: identityId,
        name: mitigationName,
        description: mitigationDescription,
        external_references: [
          makeExternalReference(
            mitigation.framework || "MITRE ATT&CK",
            `Mitigation reference for ${mitigationName}.`,
            mitigation.id,
          ),
        ],
      };

      pushObject(courseOfActionObject);
      pushRelationship("mitigates", courseOfActionId, indicatorId);
    }
  }

  const observedSummary = buildObservedSummary({
    whoisData,
    history,
    pe_header,
    abuseipdb,
  });

  const reportDescriptionParts = [
    correlationInsights ||
      `OpenCTI-compatible STIX 2.1 report for ${indicator}.`,
    detectionSummary,
    observedSummary,
  ];

  if (cveRiskScore) {
    reportDescriptionParts.push(
      `CVE risk score summary: ${JSON.stringify(cveRiskScore)}.`,
    );
  }

  if (reportId) {
    reportDescriptionParts.push(`Source report ID: ${reportId}.`);
  }

  const reportObject = {
    type: "report",
    spec_version: "2.1",
    id: reportStixId,
    created,
    modified: created,
    created_by_ref: identityId,
    name: `Threat Intelligence Report - ${cleanString(reportId, indicator)}`,
    description: reportDescriptionParts.join("\n\n"),
    published: created,
    report_types: ["threat-report"],
    labels: ["cti-report", threatLevel],
    object_refs: [...new Set(objectRefs)],
    external_references: [
      makeExternalReference(
        "VirusTotal",
        "VirusTotal enrichment source used for security vendor analysis and detection statistics.",
      ),
      makeExternalReference(
        "AbuseIPDB",
        "AbuseIPDB enrichment source used for IP reputation, abuse confidence score, and abuse report data.",
      ),
      makeExternalReference(
        "MISP",
        "MISP threat intelligence source used for community correlation, event matching, and threat context.",
      ),
      makeExternalReference(
        "NVD",
        "National Vulnerability Database source used for CVE correlation and vulnerability enrichment.",
      ),
      makeExternalReference(
        "MITRE ATT&CK",
        "MITRE ATT&CK knowledge base used for technique and mitigation mapping.",
      ),
      makeExternalReference(
        "WHOIS",
        "WHOIS or RDAP enrichment source used for registration, network, and ownership metadata.",
      ),
    ],
  };

  objects.push(reportObject);

  return {
    type: "bundle",
    id: stixId("bundle"),
    objects,
  };
}
