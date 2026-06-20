// src/services/whois.ts
// WHOIS Service
// - IP WHOIS     : RIPE REST API
// - Domain WHOIS : Parser raw WHOIS dari VirusTotal

export interface WHOISTimestamps {
  inetnum_created: string | null;
  inetnum_last_modified: string | null;
  org_created: string | null;
  org_last_modified: string | null;
  route_created: string | null;
  route_last_modified: string | null;
}

export interface WHOISIPAddress {
  range_start: string | null;
  range_end: string | null;
  cidr: string | null;
}

export interface WHOISCTISource {
  source: string;
  filtered: boolean;
}

export interface WHOISAuthor {
  org_name: string | null;
  org_id: string | null;
  maintainers: string[];
  admin_contact: string | null;
  tech_contact: string | null;
  abuse_email: string | null;
  country: string | null;
}

export interface WHOISResult {
  timestamps: WHOISTimestamps;
  ip_address: WHOISIPAddress;
  cti_source: WHOISCTISource;
  author: WHOISAuthor;
}

// DOMAIN WHOIS khusus VirusTotal/raw WHOIS
export interface DomainWHOISResult {
  timestamps: {
    registered: string | null;
    last_modified: string | null;
    expiry: string | null;
  };
  author: {
    org_name: string | null;
    country: string | null;
  };
}

// ── Helper RIPE ───────────────────────────────────────────────
function getAttr(attributes: any[], key: string): string | null {
  const found = attributes.find((a: any) => a.name === key);
  return found?.value ?? null;
}

function getAllAttr(attributes: any[], key: string): string[] {
  return attributes.filter((a: any) => a.name === key).map((a: any) => a.value);
}

// ── Helper Domain WHOIS ───────────────────────────────────────
function extractField(raw: string, field: string): string | null {
  const regex = new RegExp(`${field}:\\s*(.+)`, "i");
  const match = raw.match(regex);
  return match?.[1]?.trim() ?? null;
}

// Untuk input DOMAIN dari raw WHOIS VirusTotal
export function parseDomainWHOIS(rawWhois: string): DomainWHOISResult {
  return {
    timestamps: {
      registered: extractField(rawWhois, "Create date"),
      last_modified: extractField(rawWhois, "Update date"),
      expiry: extractField(rawWhois, "Expiry date"),
    },
    author: {
      org_name: extractField(rawWhois, "Registrant company"),
      country: extractField(rawWhois, "Registrant country"),
    },
  };
}

// ── Main fetch IP WHOIS dari RIPE ──────────────────────────────
export async function fetchWHOIS(ip: string): Promise<WHOISResult | null> {
  try {
    const url = `https://rest.db.ripe.net/search.json?query-string=${ip}&type-filter=inetnum&flags=no-filtering`;

    const res = await fetch(url, {
      headers: { Accept: "application/json" },
    });

    if (!res.ok) {
      console.warn(`[WHOIS] RIPE API error: ${res.status}`);
      return null;
    }

    const json = await res.json();
    const objects: any[] = json?.objects?.object ?? [];

    const inetnumObj = objects.find((o: any) => o.type === "inetnum");
    const inetnumAttrs: any[] = inetnumObj?.attributes?.attribute ?? [];

    const orgId = getAttr(inetnumAttrs, "org");
    let orgAttrs: any[] = [];

    if (orgId) {
      const orgRes = await fetch(
        `https://rest.db.ripe.net/ripe/organisation/${orgId}.json`,
        { headers: { Accept: "application/json" } },
      );

      if (orgRes.ok) {
        const orgJson = await orgRes.json();
        orgAttrs = orgJson?.objects?.object?.[0]?.attributes?.attribute ?? [];
      }
    }

    const routeRes = await fetch(
      `https://rest.db.ripe.net/search.json?query-string=${ip}&type-filter=route&flags=no-filtering`,
      { headers: { Accept: "application/json" } },
    );

    let routeAttrs: any[] = [];

    if (routeRes.ok) {
      const routeJson = await routeRes.json();
      const routeObj = routeJson?.objects?.object?.[0];
      routeAttrs = routeObj?.attributes?.attribute ?? [];
    }

    const inetnumRaw = getAttr(inetnumAttrs, "inetnum");

    let rangeStart: string | null = null;
    let rangeEnd: string | null = null;

    if (inetnumRaw) {
      const parts = inetnumRaw.split(" - ");
      rangeStart = parts[0]?.trim() ?? null;
      rangeEnd = parts[1]?.trim() ?? null;
    }

    const cidr = getAttr(routeAttrs, "route");

    const timestamps: WHOISTimestamps = {
      inetnum_created: getAttr(inetnumAttrs, "created"),
      inetnum_last_modified: getAttr(inetnumAttrs, "last-modified"),
      org_created: getAttr(orgAttrs, "created"),
      org_last_modified: getAttr(orgAttrs, "last-modified"),
      route_created: getAttr(routeAttrs, "created"),
      route_last_modified: getAttr(routeAttrs, "last-modified"),
    };

    const ip_address: WHOISIPAddress = {
      range_start: rangeStart,
      range_end: rangeEnd,
      cidr,
    };

    const sourceRaw = getAttr(inetnumAttrs, "source") ?? "RIPE";

    const cti_source: WHOISCTISource = {
      source: sourceRaw.replace("# Filtered", "").trim(),
      filtered: sourceRaw.includes("# Filtered"),
    };

    const orgName =
      getAttr(orgAttrs, "org-name") ?? getAttr(inetnumAttrs, "org") ?? null;

    const author: WHOISAuthor = {
      org_name: orgName,
      org_id: getAttr(inetnumAttrs, "org"),
      maintainers: getAllAttr(inetnumAttrs, "mnt-by"),
      admin_contact: getAttr(inetnumAttrs, "admin-c"),
      tech_contact: getAttr(inetnumAttrs, "tech-c"),
      abuse_email:
        getAttr(orgAttrs, "abuse-mailbox") ??
        getAttr(inetnumAttrs, "abuse-mailbox") ??
        null,
      country: getAttr(inetnumAttrs, "country"),
    };

    return {
      timestamps,
      ip_address,
      cti_source,
      author,
    };
  } catch (err) {
    console.error("[WHOIS] fetch error:", err);
    return null;
  }
}
