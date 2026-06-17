function extractCVEsFromText(text: string): string[] {
  const matches = text.match(/CVE[-_]\d{4}[-_]\d{4,7}/gi) ?? [];

  return [...new Set(matches.map((c) => c.replace(/_/g, "-").toUpperCase()))];
}

function normalizeIocType(type: string) {
  const cleanType = String(type || "")
    .toLowerCase()
    .trim();

  if (
    cleanType === "ip" ||
    cleanType === "ip_address" ||
    cleanType === "ip address"
  ) {
    return "ip";
  }

  if (cleanType === "domain") {
    return "domain";
  }

  if (cleanType === "url" || cleanType === "urls" || cleanType === "uri") {
    return "url";
  }

  if (
    cleanType === "hash" ||
    cleanType === "file" ||
    cleanType === "md5" ||
    cleanType === "sha1" ||
    cleanType === "sha256"
  ) {
    return "file";
  }

  return cleanType;
}

function detectIocTypeFromIndicator(indicator: string, fallbackType: string) {
  const cleanIndicator = indicator.trim();

  // Paling penting: cek URL dulu
  if (/^https?:\/\//i.test(cleanIndicator)) {
    return "url";
  }

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(cleanIndicator)) {
    return "ip";
  }

  if (
    /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(cleanIndicator)
  ) {
    return "file";
  }

  return normalizeIocType(fallbackType);
}

function buildVirusTotalEndpoint(indicator: string, type: string) {
  const cleanIndicator = indicator.trim();
  const cleanType = detectIocTypeFromIndicator(cleanIndicator, type);

  if (cleanType === "ip") {
    return `ip_addresses/${encodeURIComponent(cleanIndicator)}`;
  }

  if (cleanType === "domain") {
    const domain = cleanIndicator
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "");

    return `domains/${encodeURIComponent(domain)}`;
  }

  if (cleanType === "url") {
    const urlId = Buffer.from(cleanIndicator).toString("base64url");
    return `urls/${urlId}`;
  }

  if (cleanType === "file") {
    return `files/${encodeURIComponent(cleanIndicator)}`;
  }

  throw new Error(`Unsupported IOC type: ${type}`);
}

const EMPTY_STATS = {
  malicious: 0,
  suspicious: 0,
  harmless: 0,
  undetected: 0,
};

export async function fetchVirusTotal(indicator: string, type: string) {
  const API_KEY = process.env.VT_API_KEY;

  if (!API_KEY) {
    throw new Error("VT_API_KEY belum ada di file .env");
  }

  const cleanType = detectIocTypeFromIndicator(indicator, type);
  const endpoint = buildVirusTotalEndpoint(indicator, type);

  const vtUrl = `https://www.virustotal.com/api/v3/${endpoint}`;

  console.log("[VirusTotal] Request:", vtUrl);

  const res = await fetch(vtUrl, {
    headers: {
      "x-apikey": API_KEY,
      accept: "application/json",
    },
  });

  const rawText = await res.text();

  if (res.status === 404) {
    console.warn(
      "[VirusTotal] IOC tidak ditemukan atau endpoint tidak cocok:",
      {
        indicator,
        type,
        endpoint,
      },
    );

    return {
      indicator,
      type,
      found: false,
      threatLevel: "LOW",
      stats: EMPTY_STATS,
      total: 0,
      whois: null,
      virustotal: {
        indicator,
        meaningful_name: null,
        type_description: null,
        file_size: null,
        history: null,
        pe_header: null,
        detection_summary: {
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0,
          total_vendors: 0,
          detection_rate: "0%",
        },
        popular_threat_classification: {
          popular_threat_category: null,
          popular_threat_name: [],
        },
        tags: [],
        behavior_summary: null,
        sigma_analysis_results: [],
        crowdsourced_context: [],
        cve_extracted: [],
        yara_cves: [],
      },
      vendors: [],
    };
  }

  if (!res.ok) {
    console.error("[VirusTotal] Error body:", rawText);
    throw new Error(`VirusTotal API error: ${res.status} - ${rawText}`);
  }

  const json = JSON.parse(rawText);
  const attr = json.data?.attributes ?? {};

  const stats = attr.last_analysis_stats ?? EMPTY_STATS;
  const results = attr.last_analysis_results ?? {};

  const vendors = Object.entries(results).map(([vendor, value]: any) => ({
    vendor,
    category: value.category,
    result: value.result,
  }));

  const total =
    (stats.malicious ?? 0) +
    (stats.suspicious ?? 0) +
    (stats.harmless ?? 0) +
    (stats.undetected ?? 0);

  const threatLevel =
    (stats.malicious ?? 0) >= 10
      ? "CRITICAL"
      : (stats.malicious ?? 0) > 0
        ? "HIGH"
        : (stats.suspicious ?? 0) > 0
          ? "MEDIUM"
          : "LOW";

  const meaningfulName = attr.meaningful_name ?? attr.name ?? null;
  const typeDescription = attr.type_description ?? null;
  const fileSize = attr.size ?? null;

  const detectionRate =
    total > 0
      ? (((stats.malicious ?? 0) / total) * 100).toFixed(2) + "%"
      : "0%";

  const popularThreatCategory =
    attr.popular_threat_classification?.popular_threat_category?.[0]?.value ??
    null;

  const popularThreatNames: string[] =
    attr.popular_threat_classification?.popular_threat_name?.map(
      (t: any) => t.value,
    ) ?? [];

  const tags: string[] = attr.tags ?? [];

  let behaviorSummary = null;

  const isFileHash = cleanType === "file";

  if (isFileHash) {
    const behaviorRes = await fetch(
      `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator.trim())}/behaviours`,
      {
        headers: {
          "x-apikey": API_KEY,
          accept: "application/json",
        },
      },
    );

    if (behaviorRes.ok) {
      const behaviorJson = await behaviorRes.json();
      const sandboxes = behaviorJson.data ?? [];

      const networkCommunications = new Set<string>();
      const dropsFiles: string[] = [];
      const registryModifications: string[] = [];
      const processesCreated: string[] = [];
      let filesEncrypted = false;

      for (const sandbox of sandboxes) {
        const b = sandbox.attributes;

        b?.dns_lookups?.forEach((d: any) => {
          if (d.hostname) networkCommunications.add(d.hostname);
        });

        b?.files_dropped?.forEach((f: any) => {
          if (f.path) dropsFiles.push(f.path.split("\\").pop());
        });

        b?.registry_keys_set?.forEach((r: any) => {
          if (r.key) registryModifications.push(r.key);
        });

        b?.processes_created?.forEach((p: string) => {
          processesCreated.push(p);
        });

        if (
          b?.files_dropped?.some(
            (f: any) => f.path?.includes(".wncry") || f.path?.includes(".wnry"),
          )
        ) {
          filesEncrypted = true;
        }
      }

      behaviorSummary = {
        network_communications: [...networkCommunications],
        files_encrypted: filesEncrypted,
        drops_files: [...new Set(dropsFiles)],
        registry_modifications: [...new Set(registryModifications)],
        processes_created: [...new Set(processesCreated)],
      };
    }
  }

  const history = isFileHash
    ? {
        creation_time: attr.creation_date
          ? new Date(attr.creation_date * 1000).toISOString()
          : null,
        first_seen_itw: attr.first_seen_itw_date
          ? new Date(attr.first_seen_itw_date * 1000).toISOString()
          : null,
        first_submission: attr.first_submission_date
          ? new Date(attr.first_submission_date * 1000).toISOString()
          : null,
        last_submission: attr.last_submission_date
          ? new Date(attr.last_submission_date * 1000).toISOString()
          : null,
        last_analysis: attr.last_analysis_date
          ? new Date(attr.last_analysis_date * 1000).toISOString()
          : null,
      }
    : null;

  const PE_MACHINE_TYPES: Record<number, string> = {
    0x14c: "Intel 386",
    0x8664: "x64 (AMD64)",
    0xaa64: "ARM64",
    0x1c0: "ARM",
    0x200: "Intel Itanium",
  };

  const pe_header = isFileHash
    ? {
        target_machine:
          PE_MACHINE_TYPES[attr.pe_info?.machine_type] ??
          attr.pe_info?.machine_type ??
          null,
        compilation_timestamp: attr.creation_date
          ? new Date(attr.creation_date * 1000).toISOString()
          : null,
        entry_point: attr.pe_info?.entry_point ?? null,
        contained_sections: attr.pe_info?.sections?.length ?? null,
      }
    : null;

  const yaraResults = attr.crowdsourced_yara_results ?? [];

  let yaraTextBlob = "";

  for (const rule of yaraResults) {
    yaraTextBlob += `
      ${rule.rule_name ?? ""}
      ${rule.description ?? ""}
      ${rule.source ?? ""}
    `;
  }

  const yaraCVEs = extractCVEsFromText(yaraTextBlob);

  const sigmaResults: {
    rule_id: string;
    rule_title: string;
    severity: string;
  }[] = [];

  const sigmaRaw = attr.crowdsourced_ids_results ?? [];

  for (const rule of sigmaRaw) {
    sigmaResults.push({
      rule_id: rule.rule_id ?? "",
      rule_title: rule.rule_msg ?? "",
      severity: rule.alert_severity?.toUpperCase() ?? "INFO",
    });
  }

  const crowdsourcedContext: {
    rule_title: string;
    rule_msg?: string;
    severity: string;
    source?: string;
    cve?: string[];
  }[] = [];

  const rawContext = attr.crowdsourced_ids_results ?? [];

  for (const ctx of rawContext) {
    const cveMatches = (ctx.rule_msg ?? "").match(/CVE-\d{4}-\d{4,7}/gi) ?? [];

    crowdsourcedContext.push({
      rule_title: ctx.rule_msg ?? ctx.rule_id ?? "",
      severity: ctx.alert_severity?.toUpperCase() ?? "INFO",
      source: ctx.rule_source ?? null,
      cve: cveMatches,
    });
  }

  const crowdsourcedContextRaw = attr.crowdsourced_context ?? [];

  const crowdsourcedContextItems = crowdsourcedContextRaw.map((ctx: any) => {
    const detailText =
      ctx.detail ??
      ctx.details ??
      ctx.description ??
      ctx.message ??
      ctx.text ??
      "";

    const titleText = ctx.title ?? ctx.heading ?? "Untitled";
    const sourceText = ctx.source ?? ctx.source_name ?? ctx.vendor ?? null;
    const severityText =
      ctx.severity ?? ctx.alert_severity ?? ctx.level ?? "LOW";

    const textBlob = [ctx.detail, ctx.title, ctx.message]
      .filter(Boolean)
      .join(" ");

    const cveMatches = textBlob.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];

    return {
      title: titleText,
      detail: detailText,
      source: sourceText,
      severity: severityText,
      timestamp: ctx.timestamp ?? null,
      cve: cveMatches,
      link: ctx.link ?? null,
    };
  });

  const allCveFromContext = [
    ...crowdsourcedContext.flatMap((c) => c.cve ?? []),
    ...crowdsourcedContextItems.flatMap((c: any) => c.cve ?? []),
  ].map((c) => c.toUpperCase());

  const cveExtracted = [
    ...new Set(
      [
        ...tags.filter((t: string) => /^CVE[-_]\d{4}[-_]\d{4,7}$/i.test(t)),
        ...allCveFromContext,
        ...yaraCVEs,
      ].map((c) => c.replace(/_/g, "-").toUpperCase()),
    ),
  ];

  return {
    indicator,
    type,
    found: true,
    threatLevel,
    stats,
    total,
    whois: attr.whois ?? null,
    virustotal: {
      indicator,
      meaningful_name: meaningfulName,
      type_description: typeDescription,
      file_size: fileSize,
      history,
      pe_header,

      detection_summary: {
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
        total_vendors: total,
        detection_rate: detectionRate,
      },

      popular_threat_classification: {
        popular_threat_category: popularThreatCategory,
        popular_threat_name: popularThreatNames,
      },

      tags,
      behavior_summary: behaviorSummary,
      sigma_analysis_results: sigmaResults,
      crowdsourced_context: crowdsourcedContextItems,
      cve_extracted: cveExtracted,
      yara_cves: yaraCVEs,
    },
    vendors,
  };
}
