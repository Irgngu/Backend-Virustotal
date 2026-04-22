import axios from "axios";

export async function searchMISP(indicator: string) {
  try {
    const MISP_URL = process.env.MISP_URL || "http://localhost";
    const MISP_API_KEY = process.env.MISP_API_KEY || "";

    const res = await axios.post(
      `${MISP_URL}/attributes/restSearch`,
      {
        value: indicator,
        returnFormat: "json",
        limit: 50,
      },
      {
        headers: {
          Authorization: MISP_API_KEY.trim(),
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        timeout: 15000,
      }
    );

    const attrs = res.data?.response?.Attribute || [];

    if (!attrs || attrs.length === 0) {
      return {
        matchCount: 0,
        confidence: "Low",
        threatLevel: "Unknown",
        sourceOrg: "-",
        lastUpdated: "-",
        published: "No",
        correlation: "Unknown",
        threatActor: "-",
        tlp: "-",
        tags: [],
        campaigns: [],
      };
    }

    const first = attrs[0];
    const event = first.Event || {};

    const tags = event.Tag?.map((t: any) => t.name) || [];
    const galaxies = event.Galaxy?.map((g: any) => g.name) || [];

    const threatActor =
      galaxies.find(
        (g: string) =>
          g.toLowerCase().includes("threat") ||
          g.toLowerCase().includes("actor")
      ) ||
      galaxies[0] ||
      "-";

    const tlpTag =
      tags.find((t: string) => t.toLowerCase().includes("tlp:")) || "-";

    let confidence = "Low";
    if (attrs.length >= 10) confidence = "High";
    else if (attrs.length >= 3) confidence = "Medium";

    return {
      matchCount: attrs.length,
      confidence,
      threatLevel:
        event.threat_level_id === "1"
          ? "High"
          : event.threat_level_id === "2"
          ? "Medium"
          : event.threat_level_id === "3"
          ? "Low"
          : "Unknown",
      sourceOrg: event.Orgc?.name || "-",
      lastUpdated: event.timestamp || event.date || "-",
      published: event.published ? "Yes" : "No",
      correlation: "Enabled",
      threatActor,
      tlp: tlpTag,
      tags: tags.slice(0, 8),
      campaigns: galaxies.slice(0, 5),
    };

  } catch (err: any) {
    console.error("MISP ERROR:", err.message);
    console.error("STATUS:", err.response?.status);
    console.error("DETAIL:", err.response?.data);

    return {
      matchCount: 0,
      confidence: "Low",
      threatLevel: "Unknown",
      sourceOrg: "-",
      lastUpdated: "-",
      published: "No",
      correlation: "Unknown",
      threatActor: "-",
      tlp: "-",
      tags: [],
      campaigns: [],
    };
  }
}