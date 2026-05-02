import { Hono } from "hono";

const nvd = new Hono();

nvd.get("/", async (c) => {
  try {
    const keyword = c.req.query("keyword");

    if (!keyword) {
      return c.json({ error: "keyword query is required" }, 400);
    }

    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?keywordSearch=${encodeURIComponent(keyword)}` +
      `&resultsPerPage=5`;

    const response = await fetch(url, {
      headers: {
        apiKey: process.env.NVD_API_KEY || "",
      },
    });

    const data = await response.json();

    return c.json(data);
  } catch (error: any) {
    return c.json(
      {
        error: "Failed fetch NVD data",
        details: error.message,
      },
      500,
    );
  }
});

export default nvd;
