// src/misp.ts

import axios from "axios";

function mapThreatLevel(id: any): string | null {
  const map: Record<string, string> = {
    "1": "High",
    "2": "Medium",
    "3": "Low",
    "4": "Undefined",
  };

  return map[String(id)] || null;
}

function formatUnix(ts: any): string | null {
  const num = Number(ts);
  if (!num) return null;

  return new Date(num * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function calcConfidence(matchCount: number): string | null {
  if (matchCount >= 15) return "Very High";
  if (matchCount >= 8) return "High";
  if (matchCount >= 3) return "Medium";
  if (matchCount >= 1) return "Low";
  return null;
}

function calcScore(
  matchCount: number,
  threatLevel: string | null,
  publishedCount: number,
): number {
  let score = 0;

  score += Math.min(matchCount * 5, 40);

  if (threatLevel === "High") score += 35;
  else if (threatLevel === "Medium") score += 25;
  else if (threatLevel === "Low") score += 10;

  score += Math.min(publishedCount * 10, 30);

  return Math.min(score, 100);
}

function extractThreatActor(text: string): string | null {
  if (!text) return null;

  const patterns = [
    /APT\d+/i,
    /Black Vine/i,
    /Lazarus/i,
    /FIN\d+/i,
    /Mustang Panda/i,
    /Sandworm/i,
    /Turla/i,
    /Cozy Bear/i,
    /Fancy Bear/i,
  ];

  for (const p of patterns) {
    const match = text.match(p);
    if (match) return match[0];
  }

  return null;
}

export async function searchMISP(indicator: string) {
  try {
    const MISP_URL = process.env.MISP_URL || "http://localhost:8082";

    const MISP_API_KEY = process.env.MISP_API_KEY || "";

    const res = await axios.post(
      `${MISP_URL}/attributes/restSearch`,
      {
        value: indicator,
        returnFormat: "json",
        limit: 100,
        includeEventTags: true,
        includeContext: true,
        metadata: true,
      },
      {
        headers: {
          Authorization: MISP_API_KEY.trim(),
          "X-Auth-Token": MISP_API_KEY.trim(),
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        timeout: 20000,
      },
    );

    const attrs: any[] = res.data?.response?.Attribute || [];

    if (!attrs.length) {
      return {
        matchCount: 0,
        confidence: null,
        score: 0,
        threatLevel: null,
        sourceOrg: null,
        ownerOrg: null,

        firstRecordedChange: null,
        lastChange: null,

        firstSeen: null,
        lastSeen: null,
        lastUpdated: null,

        publishDate: null,
        firstPublishDate: null,
        lastPublishDate: null,

        eventDate: null,

        published: false,
        publishedCount: 0,
        correlation: false,

        threatActor: null,
        tlp: null,

        uuid: null,
        eventId: null,
        title: null,

        tags: [],
        campaigns: [],

        raw: res.data,
      };
    }

    // ========================
    // EVENTS
    // ========================
    const events: any[] = attrs.map((a: any) => a.Event).filter(Boolean);

    const bestEvent = events[0];

    const newestEvent = [...events].sort(
      (a: any, b: any) => Number(b.timestamp || 0) - Number(a.timestamp || 0),
    )[0];

    // ========================
    // ATTRIBUTE TIMESTAMP
    // ========================
    const attrTimes = attrs
      .map((a: any) => Number(a.timestamp || 0))
      .filter(Boolean);

    const firstRecordedChange =
      attrTimes.length > 0 ? formatUnix(Math.min(...attrTimes)) : null;

    const lastChange = newestEvent?.timestamp
      ? formatUnix(newestEvent.timestamp)
      : null;

    // ========================
    // EVENT TIMESTAMP
    // ========================
    const eventTimes = events
      .map((e: any) => Number(e.timestamp || 0))
      .filter(Boolean);

    const firstSeen =
      eventTimes.length > 0 ? formatUnix(Math.min(...eventTimes)) : null;

    const lastSeen =
      eventTimes.length > 0 ? formatUnix(Math.max(...eventTimes)) : null;

    // ========================
    // PUBLISH TIMESTAMP
    // ========================
    const publishTimes = events
      .map((e: any) => Number(e.publish_timestamp || 0))
      .filter((n: number) => n > 0);

    const firstPublishDate =
      publishTimes.length > 0 ? formatUnix(Math.min(...publishTimes)) : null;

    const lastPublishDate =
      publishTimes.length > 0 ? formatUnix(Math.max(...publishTimes)) : null;

    // ========================
    // TAGS
    // ========================
    const allTags: string[] = attrs.flatMap((a: any) => {
      const attrTags = (a.Tag || []).map((t: any) => String(t.name));

      const eventTags = (a.Event?.Tag || []).map((t: any) => String(t.name));

      return [...attrTags, ...eventTags];
    });

    const tags = [...new Set(allTags)];

    const campaigns = tags.filter(
      (t: string) => !t.toLowerCase().includes("tlp:"),
    );

    const tlp =
      tags.find((t: string) => t.toLowerCase().includes("tlp:")) || null;

    // ========================
    // PUBLISHED
    // ========================
    const published = publishTimes.length > 0;

    const publishedCount = publishTimes.length;

    // ========================
    // THREAT LEVEL
    // ========================
    const threatLevel =
      bestEvent?.ThreatLevel?.name ||
      mapThreatLevel(bestEvent?.threat_level_id);

    const confidence = calcConfidence(attrs.length);

    const score = calcScore(attrs.length, threatLevel, publishedCount);

    const title = bestEvent?.info || null;

    const threatActor = extractThreatActor(title || "");

    return {
      matchCount: attrs.length,

      confidence,

      score,

      threatLevel,

      sourceOrg: bestEvent?.Orgc?.name || null,

      ownerOrg: bestEvent?.Org?.name || null,

      firstRecordedChange,

      lastChange,

      firstSeen,

      lastSeen,

      lastUpdated: formatUnix(newestEvent?.timestamp),

      publishDate: lastPublishDate,

      firstPublishDate,

      lastPublishDate,

      eventDate: bestEvent?.date || null,

      published,

      publishedCount,

      correlation: attrs.some((a: any) => a.disable_correlation === false),

      threatActor,

      tlp,

      uuid: bestEvent?.uuid || null,

      eventId: bestEvent?.id || null,

      title,

      tags: tags.slice(0, 10),

      campaigns: campaigns.slice(0, 8),

      raw: res.data,
    };
  } catch (err: any) {
    console.error("MISP ERROR:", err?.response?.data || err.message);

    return {
      matchCount: 0,
      confidence: null,
      score: 0,
      threatLevel: null,
      sourceOrg: null,
      ownerOrg: null,

      firstRecordedChange: null,
      lastChange: null,

      firstSeen: null,
      lastSeen: null,
      lastUpdated: null,

      publishDate: null,
      firstPublishDate: null,
      lastPublishDate: null,

      eventDate: null,

      published: false,
      publishedCount: 0,
      correlation: false,

      threatActor: null,
      tlp: null,

      uuid: null,
      eventId: null,
      title: null,

      tags: [],
      campaigns: [],

      raw: null,
    };
  }
}