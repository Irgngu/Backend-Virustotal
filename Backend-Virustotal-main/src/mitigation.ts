import fetch from "node-fetch";

const MITRE_URL =
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

interface MitreObject {
  id: string;
  type: string;
  name?: string;
  description?: string;
  external_references?: {
    source_name: string;
    external_id?: string;
  }[];
  source_ref?: string;
  target_ref?: string;
  relationship_type?: string;
}

let cache: MitreObject[] | null = null;

export async function loadMitreData(): Promise<MitreObject[]> {
  if (cache) return cache;

  const res = await fetch(MITRE_URL);
  const data: any = await res.json();

  cache = data.objects;
  return cache!; // ✅ FIX
}

// ✅ Ambil technique berdasarkan kode (T1059, dll)
export async function getTechniqueByCode(code: string) {
  const objects = await loadMitreData();

  return objects.find(
    (obj) =>
      obj.type === "attack-pattern" &&
      obj.external_references?.some(
        (ref) => ref.external_id === code
      )
  );
}

// ✅ Ambil mitigation dari technique
export async function getMitigationsByTechnique(code: string) {
  const objects = await loadMitreData();

  const technique = await getTechniqueByCode(code);
  if (!technique) return [];

  const relationships = objects.filter(
    (obj) =>
      obj.type === "relationship" &&
      obj.relationship_type === "mitigates" &&
      obj.target_ref === technique.id
  );

  const mitigations = relationships
    .map((rel) =>
      objects.find(
        (obj) =>
          obj.id === rel.source_ref &&
          obj.type === "course-of-action"
      )
    )
    .filter(Boolean);

  return mitigations;
}

// ===============================
// 🔥 CONFIDENCE CALCULATION
// ===============================
export function calculateConfidence(data: any): string {
  let score = 0;

  score += data.vt_score || 0;
  score += data.abuse_score || 0;

  if (data.misp_confidence === "High") score += 30;
  else if (data.misp_confidence === "Medium") score += 15;

  if (score >= 80) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

// ===============================
// 🔥 MAP TO MITRE TECHNIQUE
// ===============================
export function mapToMITRE(data: any): string | null {

  // 🔴 Brute force / scanning (IP abuse tinggi)
  if (data.type === "ip" && data.abuse_score > 50) {
    return "T1110"; // Brute Force
  }

  // 🔴 Phishing dari MISP tag
  if (data.tags?.some((t: string) => t.toLowerCase().includes("phishing"))) {
    return "T1566";
  }

  // 🔴 Malware / script execution
  if (data.vt_score > 5) {
    return "T1059";
  }

  // 🔴 fallback
  return null;
}