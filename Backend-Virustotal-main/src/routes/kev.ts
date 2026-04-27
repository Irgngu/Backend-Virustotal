import { Hono } from "hono";

const kev = new Hono();

let cache: any = null;
let lastFetch = 0;

kev.get("/", async (c) => {
  try {
    const cve = c.req.query("cve");

    if (!cve) {
      return c.json({ error: "cve query is required" }, 400);
    }

    const now = Date.now();

    if (!cache || now - lastFetch > 3600000) {
      const res = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      );

      cache = await res.json();
      lastFetch = now;
    }

    const found = cache.vulnerabilities.find((x: any) => x.cveID === cve);

    return c.json({
      cve,
      exploited: !!found,
      detail: found || null,
    });
  } catch (error: any) {
    return c.json(
      {
        error: "Failed fetch KEV data",
        details: error.message,
      },
      500,
    );
  }
});

export default kev;
