function extractCVEsFromText(text: string): string[] {
  const matches = text.match(/CVE[-_]\d{4}[-_]\d{4,7}/gi) ?? [];

  return [...new Set(matches.map((c) => c.replace(/_/g, "-").toUpperCase()))];
}

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
  // ── BARU: history + PE header (khusus file hash) ──────────────
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

  // ── BARU: crowdsourced YARA rules (INI YANG DARI SCREENSHOT) ──
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
  console.log(
    "RAW crowdsourced_context:",
    JSON.stringify(crowdsourcedContextRaw, null, 2),
  );
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

  // gabungkan semua CVE yang ditemukan
  const allCveFromContext = [
    ...crowdsourcedContext.flatMap((c) => c.cve ?? []),
    ...crowdsourcedContextItems.flatMap((c: any) => c.cve ?? []),
  ].map((c) => c.toUpperCase());

  const cveExtracted = [
    ...new Set(
      [
        ...tags.filter((t: string) => /^CVE[-_]\d{4}[-_]\d{4,7}$/i.test(t)),
        ...allCveFromContext,
        ...yaraCVEs, // 🔥 TAMBAHAN DARI YARA
      ].map((c) => c.replace(/_/g, "-").toUpperCase()),
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
      history, // ← TAMBAH
      pe_header, // ← TAMBAH

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
      yara_cves: yaraCVEs,
    },
    vendors,
  };
}
