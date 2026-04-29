// mitigation.ts
// ================================================================
// Advanced CTI Mitigation Engine
// Evidence-based MITRE ATT&CK correlation engine
// ================================================================

export interface NormalizedIndicator {
  type: string;

  // VirusTotal
  vt_score: number;
  vt_total: number;

  // AbuseIPDB
  abuse_score: number;

  // MISP
  misp_confidence: "High" | "Medium" | "Low" | string;

  // IOC context
  tags: string[];
  malware_family?: string | null;

  // optional enrichments
  threat_category?: string | null;
  source?: string | null;
}

export interface MitigationAction {
  id: string;
  name: string;
  description: string;
  framework: string;
}

export interface TechniqueMatch {
  technique: string;
  techniqueName: string;
  confidence: number;
  reasons: string[];
}

export interface TechniqueEntry {
  technique: string;
  name: string;

  score: (n: NormalizedIndicator) => number;

  reasons: (n: NormalizedIndicator) => string[];

  mitigations: MitigationAction[];
}

export interface ThreatIntelResult {
  primaryTechnique: string | null;
  primaryTechniqueName: string | null;

  techniques: TechniqueMatch[];

  mitigations: MitigationAction[];

  cve: string | null;
  cwe: string | null;
}

// ================================================================
// Helper
// ================================================================

function hasTag(
  n: NormalizedIndicator,
  values: string[]
): boolean {
  return values.some((v) =>
    n.tags?.map((t) => t.toLowerCase()).includes(v.toLowerCase())
  );
}

// ================================================================
// Technique Map
// Evidence-based scoring
// ================================================================

const TECHNIQUE_MAP: TechniqueEntry[] = [
  // ============================================================
  // PHISHING
  // ============================================================
  {
    technique: "T1566",
    name: "Phishing",

    score: (n) => {
      let score = 0;

      if (n.type === "url") score += 15;

      if (
        hasTag(n, [
          "phishing",
          "credential-phishing",
          "email"
        ])
      ) {
        score += 50;
      }

      if (n.misp_confidence === "High") score += 20;

      if (n.vt_score >= 5) score += 10;

      return score;
    },

    reasons: (n) => {
      const reasons: string[] = [];

      if (n.type === "url") {
        reasons.push("Indicator is a URL");
      }

      if (hasTag(n, ["phishing"])) {
        reasons.push("VirusTotal/MISP tagged IOC as phishing");
      }

      if (n.vt_score >= 5) {
        reasons.push("Multiple vendors flagged IOC as malicious");
      }

      return reasons;
    },

    mitigations: [
      {
        id: "M1049",
        name: "Antivirus/Antimalware",
        description:
          "Ensure endpoint AV signatures are updated and scan all systems exposed to the phishing IOC.",
        framework: "MITRE ATT&CK + NIST SP 800-83",
      },
      {
        id: "M1054",
        name: "Email Security Controls",
        description:
          "Implement SPF, DKIM, DMARC, attachment sandboxing, and malicious URL filtering.",
        framework: "OWASP + NIST",
      },
    ],
  },

  // ============================================================
  // COMMAND & CONTROL
  // ============================================================
  {
    technique: "T1071",
    name: "Application Layer Protocol (C2)",

    score: (n) => {
      let score = 0;

      if (n.type === "domain") score += 20;

      if (n.type === "ip") score += 20;

      if (
        hasTag(n, [
          "c2",
          "command-and-control",
          "trojan",
          "botnet"
        ])
      ) {
        score += 50;
      }

      if (n.abuse_score >= 50) score += 15;

      if (n.vt_score >= 10) score += 10;

      return score;
    },

    reasons: (n) => {
      const reasons: string[] = [];

      if (hasTag(n, ["c2", "botnet"])) {
        reasons.push("Threat tags indicate possible C2 behavior");
      }

      if (n.abuse_score >= 50) {
        reasons.push("High AbuseIPDB reputation score");
      }

      if (n.type === "domain" || n.type === "ip") {
        reasons.push("Indicator is network infrastructure");
      }

      return reasons;
    },

    mitigations: [
      {
        id: "M1031",
        name: "Network Intrusion Prevention",
        description:
          "Deploy IDS/IPS signatures to detect malicious outbound C2 communication.",
        framework: "MITRE ATT&CK + NIST SP 800-94",
      },
      {
        id: "M1037",
        name: "Filter Network Traffic",
        description:
          "Apply egress filtering and block known malicious destinations.",
        framework: "MITRE ATT&CK + NIST SP 800-41",
      },
    ],
  },

  // ============================================================
  // MALICIOUS FILE EXECUTION
  // ============================================================
  {
    technique: "T1204",
    name: "User Execution",

    score: (n) => {
      let score = 0;

      if (n.type.includes("hash")) score += 35;

      if (
        hasTag(n, [
          "trojan",
          "dropper",
          "downloader",
          "malware"
        ])
      ) {
        score += 40;
      }

      if (n.vt_score >= 5) score += 15;

      return score;
    },

    reasons: (n) => {
      const reasons: string[] = [];

      if (n.type.includes("hash")) {
        reasons.push("Indicator is a file hash");
      }

      if (hasTag(n, ["trojan", "malware"])) {
        reasons.push("Threat tags indicate malware delivery");
      }

      return reasons;
    },

    mitigations: [
      {
        id: "M1038",
        name: "Execution Prevention",
        description:
          "Block malicious file execution using EDR or allowlisting.",
        framework: "MITRE ATT&CK + NIST SP 800-167",
      },
      {
        id: "M1045",
        name: "Code Signing",
        description:
          "Enforce trusted signed binaries only.",
        framework: "MITRE ATT&CK + OWASP A08",
      },
    ],
  },

  // ============================================================
  // RANSOMWARE
  // ============================================================
  {
    technique: "T1486",
    name: "Data Encrypted for Impact",

    score: (n) => {
      let score = 0;

      if (
        hasTag(n, [
          "ransomware",
          "locker",
          "encryptor"
        ])
      ) {
        score += 70;
      }

      if (
        n.malware_family?.toLowerCase().includes("lockbit")
      ) {
        score += 30;
      }

      return score;
    },

    reasons: (n) => {
      const reasons: string[] = [];

      if (hasTag(n, ["ransomware"])) {
        reasons.push("Threat tags indicate ransomware behavior");
      }

      if (n.malware_family) {
        reasons.push(
          `Malware family identified: ${n.malware_family}`
        );
      }

      return reasons;
    },

    mitigations: [
      {
        id: "M1053",
        name: "Data Backup",
        description:
          "Maintain offline immutable backups and regularly test restoration.",
        framework: "MITRE ATT&CK + NIST",
      },
      {
        id: "M1027",
        name: "Password Policies",
        description:
          "Protect privileged access paths commonly targeted by ransomware operators.",
        framework: "MITRE ATT&CK",
      },
    ],
  },
];

// ================================================================
// Baseline mitigations
// ================================================================

const BASELINE_MITIGATIONS: MitigationAction[] = [
  {
    id: "NIST-IR-1",
    name: "Document & Escalate Finding",
    description:
      "Document findings and escalate incident to SOC team.",
    framework: "NIST SP 800-61r2",
  },
  {
    id: "NIST-IR-2",
    name: "Update Threat Intelligence Feeds",
    description:
      "Share IOC internally through SIEM/TIP systems.",
    framework: "NIST CSF",
  },
];

// ================================================================
// Confidence Scoring
// ================================================================

export function calculateConfidence(
  normalized: NormalizedIndicator
): "High" | "Medium" | "Low" {
  const vtRatio =
    normalized.vt_total > 0
      ? (normalized.vt_score / normalized.vt_total) * 100
      : 0;

  let score = 0;

  score += vtRatio * 0.4;

  score += normalized.abuse_score * 0.3;

  if (normalized.misp_confidence === "High") {
    score += 25;
  } else if (normalized.misp_confidence === "Medium") {
    score += 15;
  }

  if (normalized.tags.length > 0) {
    score += 15;
  }

  if (score >= 70) return "High";

  if (score >= 40) return "Medium";

  return "Low";
}

// ================================================================
// Main Analysis
// ================================================================

export async function analyzeThreatToMitigation(
  normalized: NormalizedIndicator
): Promise<ThreatIntelResult> {
  const matchedTechniques: TechniqueMatch[] = [];

  const mitigations: MitigationAction[] = [];

  const seenMitigations = new Set<string>();

  for (const entry of TECHNIQUE_MAP) {
    const confidence = entry.score(normalized);

    // threshold minimum
    if (confidence >= 40) {
      matchedTechniques.push({
        technique: entry.technique,
        techniqueName: entry.name,
        confidence,
        reasons: entry.reasons(normalized),
      });

      for (const mitigation of entry.mitigations) {
        if (!seenMitigations.has(mitigation.id)) {
          seenMitigations.add(mitigation.id);

          mitigations.push(mitigation);
        }
      }
    }
  }

  // sort by highest confidence
  matchedTechniques.sort(
    (a, b) => b.confidence - a.confidence
  );

  // append baseline mitigation
  for (const mitigation of BASELINE_MITIGATIONS) {
    if (!seenMitigations.has(mitigation.id)) {
      mitigations.push(mitigation);
    }
  }

  return {
    primaryTechnique:
      matchedTechniques[0]?.technique || null,

    primaryTechniqueName:
      matchedTechniques[0]?.techniqueName || null,

    techniques: matchedTechniques,

    mitigations,

    cve: null,
    cwe: null,
  };
}

// ================================================================
// Utility
// ================================================================

const TECHNIQUE_NAMES: Record<string, string> =
  Object.fromEntries(
    TECHNIQUE_MAP.map((t) => [
      t.technique,
      t.name,
    ])
  );

export async function getTechniqueByCode(
  code: string
): Promise<{ code: string; name: string } | null> {
  if (!code) return null;

  const name = TECHNIQUE_NAMES[code];

  return name
    ? {
        code,
        name,
      }
    : null;
}