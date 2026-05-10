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
  const attr = json.data.attributes;

  // ── sudah ada ──────────────────────────────────────────────
  const stats = attr.last_analysis_stats;
  const results = attr.last_analysis_results;

  // 🔥 ubah jadi array biar gampang dipakai
  const vendors = Object.entries(results).map(([vendor, value]: any) => ({
    vendor,
    category: value.category,
    result: value.result,
  }));
  const total =
    stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

  const threatLevel =
    stats.malicious >= 10
      ? "CRITICAL"
      : stats.malicious > 0
        ? "HIGH"
        : stats.suspicious > 0
          ? "MEDIUM"
          : "LOW";

  // ── BARU: metadata file ────────────────────────────────────
  const hash = json.data.id ?? indicator;
  const meaningfulName = attr.meaningful_name ?? attr.name ?? null;
  const typeDescription = attr.type_description ?? null;
  const fileSize = attr.size ?? null;

  // ── BARU: detection summary ────────────────────────────────
  const detectionRate =
    total > 0 ? ((stats.malicious / total) * 100).toFixed(2) + "%" : "0%";

  // ── BARU: popular threat classification ───────────────────
  const popularThreatCategory =
    attr.popular_threat_classification?.popular_threat_category?.[0]?.value ??
    null;
  const popularThreatNames: string[] =
    attr.popular_threat_classification?.popular_threat_name?.map(
      (t: any) => t.value,
    ) ?? [];

  // ── BARU: tags ─────────────────────────────────────────────
  const tags: string[] = attr.tags ?? [];

  // ── BARU: behavior summary (hanya tersedia di endpoint /files/{hash}/behaviours) ──
  // Perlu request tambahan khusus untuk file hash
  let behaviorSummary = null;

  const isFileHash = type === "file" || type.startsWith("hash");

  if (isFileHash) {
    const behaviorRes = await fetch(
      `https://www.virustotal.com/api/v3/files/${indicator}/behaviours`,
      { headers: { "x-apikey": API_KEY! } },
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

  // ── BARU: sigma rules ──────────────────────────────────────
  // Diambil dari crowdsourced_ids_results (tersedia di respons utama)
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

  // ── BARU: crowdsourced context (tersedia untuk IP, domain, file) ──
  const crowdsourcedContext: {
    rule_title: string;
    rule_msg?: string;
    severity: string;
    source?: string;
    cve?: string[];
  }[] = [];

  const rawContext = attr.crowdsourced_ids_results ?? [];
  for (const ctx of rawContext) {
    // ekstrak CVE dari rule_msg atau rule_raw jika ada
    const cveMatches = (ctx.rule_msg ?? "").match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
    crowdsourcedContext.push({
      rule_title: ctx.rule_msg ?? ctx.rule_id ?? "",
      severity: ctx.alert_severity?.toUpperCase() ?? "INFO",
      source: ctx.rule_source ?? null,
      cve: cveMatches,
    });
  }

  // ── BARU: crowdsourced_context khusus IP/domain ──
  // Field ini berbeda dari crowdsourced_ids_results, khusus ada di IP & domain
  const crowdsourcedContextRaw = attr.crowdsourced_context ?? [];
  const crowdsourcedContextItems = crowdsourcedContextRaw.map((ctx: any) => {
    const textBlob = [ctx.detail, ctx.title, ctx.message]
      .filter(Boolean)
      .join(" ");

    const cveMatches = textBlob.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];

    return {
      detail: ctx.detail ?? "",
      severity: ctx.severity ?? "LOW",
      source: ctx.source ?? undefined,
      timestamp: ctx.timestamp ?? null,
      cve: cveMatches,
    };
  });

  // gabungkan semua CVE yang ditemukan
  const allCveFromContext = [
    ...crowdsourcedContext.flatMap((c) => c.cve ?? []),
    ...crowdsourcedContextItems.flatMap((c: any) => c.cve ?? []),
  ].map((c) => c.toUpperCase());

  const cveExtracted = [
    ...new Set(
      [
        ...tags.filter((t: string) => /^CVE-\d{4}-\d{4,7}$/i.test(t)),
        ...allCveFromContext,
      ].map((c) => c.toUpperCase()),
    ),
  ];

  return {
    indicator,
    type,
    threatLevel,
    stats,
    total,
    virustotal: {
      indicator,
      meaningful_name: meaningfulName,
      type_description: typeDescription,
      file_size: fileSize,

      detection_summary: {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        harmless: stats.harmless,
        undetected: stats.undetected,
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
    },
    vendors,
  };
}
