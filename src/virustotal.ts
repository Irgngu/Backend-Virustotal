export async function fetchVirusTotal(indicator: string, type: string) {
  const API_KEY = process.env.VT_API_KEY;

  let endpoint = "";

  if (type === "ip") {
    endpoint = `ip_addresses/${indicator}`;
  } else if (type === "domain") {
    endpoint = `domains/${indicator}`;
  } else if (type === "url") {
    endpoint = `urls/${indicator}`;
  } else {
    endpoint = `files/${indicator}`;
  }

  const res = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
    headers: {
      "x-apikey": API_KEY!,
    },
  });

  if (!res.ok) {
    throw new Error(`VirusTotal API error: ${res.status}`);
  }

  const json = await res.json();

  // 🔥 ambil stats (6/94 dll)
  const stats = json.data.attributes.last_analysis_stats;

  // 🔥 ambil vendor results
  const results = json.data.attributes.last_analysis_results;

  // 🔥 ubah jadi array biar gampang dipakai
  const vendors = Object.entries(results).map(([vendor, value]: any) => ({
    vendor,
    category: value.category,
    result: value.result,
  }));

  const threatLevel =
  stats.malicious > 0
    ? "HIGH"
    : stats.suspicious > 0
    ? "MEDIUM"
    : "LOW";

  return {
    indicator,
    type,
    threatLevel,
    stats,
    total:
      stats.malicious +
      stats.suspicious +
      stats.harmless +
      stats.undetected,
    vendors,
    
  };
}
