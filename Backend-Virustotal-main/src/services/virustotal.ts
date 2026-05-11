function extractCVEsFromText(text: string): string[] {
  const matches = text.match(/CVE[-_]\d{4}[-_]\d{4,7}/gi) ?? [];

  return [
    ...new Set(
      matches.map((c) =>
        c.replace(/_/g, "-").toUpperCase()
      )
    ),
  ];
}

export async function fetchVirusTotal(indicator: string, type: string) {
  const API_KEY = process.env.VT_API_KEY;

  // ✅ FIX: type flags defined once, used throughout
  const isFileHash = type === "file" || type.startsWith("hash");
  const isURL = type === "url";
  const isIP = type === "ip";
  const isDomain = type === "domain";

  let endpoint = "";

  if (isIP) {
    endpoint = `ip_addresses/${indicator}`;
  } else if (isDomain) {
    endpoint = `domains/${indicator}`;
  } else if (isURL) {
    // ✅ FIX: base64url encode required by VT API for URL lookups
    const encoded = Buffer.from(indicator)
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    endpoint = `urls/${encoded}`;
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

  const stats = attr.last_analysis_stats;
  const results = attr.last_analysis_results;

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

  const hash = json.data.id ?? indicator;

  // ✅ FIX: file-only fields guarded with isFileHash
  const meaningfulName  = isFileHash ? (attr.meaningful_name ?? attr.name ?? null) : null;
  const typeDescription = isFileHash ? (attr.type_description ?? null) : null;
  const fileSize        = isFileHash ? (attr.size ?? null) : null;

  const detectionRate =
    total > 0 ? ((stats.malicious / total) * 100).toFixed(2) + "%" : "0%";

  const popularThreatCategory =
    attr.popular_threat_classification?.popular_threat_category?.[0]?.value ??
    null;
  const popularThreatNames: string[] =
    attr.popular_threat_classification?.popular_threat_name?.map(
      (t: any) => t.value,
    ) ?? [];

  const tags: string[] = attr.tags ?? [];

  // ✅ FIX: behaviours fetch — file hash only
  let behaviorSummary = null;

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

  // ✅ FIX: YARA — file hash only
  const yaraResults = isFileHash ? (attr.crowdsourced_yara_results ?? []) : [];

  let yaraTextBlob = "";

  for (const rule of yaraResults) {
    yaraTextBlob += `
      ${rule.rule_name ?? ""}
      ${rule.description ?? ""}
      ${rule.source ?? ""}
    `;
  }

  const yaraCVEs = extractCVEsFromText(yaraTextBlob);

  // sigma — file hash only (unchanged logic, just guarded)
  const sigmaResults: {
    rule_id: string;
    rule_title: string;
    severity: string;
  }[] = [];
  const sigmaRaw = isFileHash ? (attr.crowdsourced_ids_results ?? []) : [];
  for (const rule of sigmaRaw) {
    sigmaResults.push({
      rule_id: rule.rule_id ?? "",
      rule_title: rule.rule_msg ?? "",
      severity: rule.alert_severity?.toUpperCase() ?? "INFO",
    });
  }

  // crowdsourced_ids_results context — file hash only
  const crowdsourcedContext: {
    rule_title: string;
    rule_msg?: string;
    severity: string;
    source?: string;
    cve?: string[];
  }[] = [];

  const rawContext = isFileHash ? (attr.crowdsourced_ids_results ?? []) : [];
  for (const ctx of rawContext) {
    const cveMatches = (ctx.rule_msg ?? "").match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
    crowdsourcedContext.push({
      rule_title: ctx.rule_msg ?? ctx.rule_id ?? "",
      severity: ctx.alert_severity?.toUpperCase() ?? "INFO",
      source: ctx.rule_source ?? null,
      cve: cveMatches,
    });
  }

  // ✅ FIX: crowdsourced_context — IP/domain only
  const crowdsourcedContextRaw = (isIP || isDomain)
    ? (attr.crowdsourced_context ?? [])
    : [];

  console.log("RAW crowdsourced_context:", JSON.stringify(crowdsourcedContextRaw, null, 2));

  const crowdsourcedContextItems = crowdsourcedContextRaw.map((ctx: any) => {
    const detailText =
      ctx.detail ??
      ctx.details ??
      ctx.description ??
      ctx.message ??
      ctx.text ??
      "";

    const titleText =
      ctx.title ??
      ctx.heading ??
      "Untitled";

    const sourceText =
      ctx.source ??
      ctx.source_name ??
      ctx.vendor ??
      null;

    const severityText =
      ctx.severity ??
      ctx.alert_severity ??
      ctx.level ??
      "LOW";

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
      ].map((c) =>
        c.replace(/_/g, "-").toUpperCase()
      ),
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
      yara_cves: yaraCVEs,
    },
    vendors,
  };
}