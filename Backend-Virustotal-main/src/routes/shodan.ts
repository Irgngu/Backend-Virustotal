import { Hono } from "hono";

const shodan = new Hono();

shodan.get("/", async (c) => {
  try {
    const ip = c.req.query("ip");

    if (!ip) {
      return c.json({ error: "ip query is required" }, 400);
    }

    const res = await fetch(
      `https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_API_KEY}`,
    );

    if (!res.ok) {
      const errText = await res.text();

      return c.json(
        {
          error: "Failed fetch Shodan",
          status: res.status,
          details: errText,
        },
        {
          status: res.status as any,
        },
      );
    }

    const data = await res.json();
    console.log(JSON.stringify(data, null, 2));

    const banners = Array.isArray(data?.data) ? data.data : [];

    const firstBanner =
      banners.find(
        (item: any) => item?.product || item?.http?.server || item?.ssl?.cert,
      ) ||
      banners[0] ||
      {};

    const product =
      firstBanner?.product ||
      firstBanner?.http?.server ||
      firstBanner?.http?.headers?.server ||
      data?.product ||
      null;

    const version = firstBanner?.version || null;

    const cert = firstBanner?.ssl?.cert || null;

    const certificate = cert
      ? {
          subject: cert?.subject?.CN || null,

          issuer: cert?.issuer?.CN || null,

          serial: cert?.serial || null,

          expires: cert?.expires || null,
        }
      : null;

    return c.json({
      ip,

      product,
      version,

      ports: data?.ports || [],
      hostnames: data?.hostnames || [],

      org: data?.org || null,
      isp: data?.isp || null,
      os: data?.os || null,

      country: data?.country_name || null,

      city: data?.city || null,

      certificate,

      rawCount: banners.length,
    });
  } catch (error: any) {
    return c.json(
      {
        error: "Failed fetch Shodan",
        details: error.message,
      },
      500,
    );
  }
});

export default shodan;
