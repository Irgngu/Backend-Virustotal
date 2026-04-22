// src/mitigation.ts

export interface NormalizedData {
  type: string;
  vt_score: number;
  vt_total: number;
  abuse_score: number;
  misp_confidence: string;
  tags?: string[];
}

// 🔥 Confidence Scoring
export function calculateConfidence(data: NormalizedData): number {
  let score = 0;

  score += (data.vt_score / Math.max(data.vt_total, 1)) * 40;
  score += (data.abuse_score / 100) * 30;

  if (data.misp_confidence === "High") score += 30;
  else if (data.misp_confidence === "Medium") score += 15;

  return Math.min(score, 100);
}

// 🔥 MITRE Mapping
export function mapToMITRE(data: NormalizedData) {
  if (data.tags?.includes("c2")) {
    return { technique: "T1071", name: "Command & Control" };
  }

  if (data.type === "ip" && data.abuse_score > 70) {
    return { technique: "T1595", name: "Active Scanning" };
  }

  if (data.tags?.includes("malware")) {
    return { technique: "T1204", name: "User Execution" };
  }

  return null;
}

// 🔥 Mitigation Mapping
const mitigationMap: Record<string, string[]> = {
  T1071: [
    "Block outbound command-and-control traffic",
    "Monitor DNS queries for anomalies",
    "Deploy EDR to detect beaconing"
  ],
  T1595: [
    "Block scanning IP at firewall",
    "Enable IDS/IPS for reconnaissance detection",
    "Monitor repeated connection attempts"
  ],
  T1204: [
    "Restrict execution of unknown files",
    "Enable application whitelisting",
    "Use sandboxing for suspicious files"
  ]
};

// 🔥 Final Generator
export function generateMitigation(data: NormalizedData): string[] {
  const confidence = calculateConfidence(data);
  const mitre = mapToMITRE(data);

  // 🔥 Anti false-positive
  if (confidence < 40) {
    return ["Monitor only — low confidence indicator"];
  }

  let actions: string[] = [];

  if (confidence > 70) {
    actions.push("Immediately block the indicator across security controls");
  }

  if (confidence > 50) {
    actions.push("Conduct forensic investigation on affected systems");
  }

  if (mitre) {
  actions.push(`[${mitre.technique}] ${mitre.name}`);

  const mitreActions = mitigationMap[mitre.technique] || [];
  actions.push(...mitreActions);
  }
  
  actions.push(
    "Update threat intelligence feeds",
    "Monitor logs for related activity",
    "Document findings and escalate if needed"
  );

  return actions;
}