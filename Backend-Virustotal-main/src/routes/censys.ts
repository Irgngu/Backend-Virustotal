import { Hono } from "hono";
import { getCensysHost, getCensysDomain } from "../services/censys.js";

const censys = new Hono();

censys.get("/:ioc", async (c) => {
  try {
    const ioc = c.req.param("ioc");

    if (!ioc) {
      return c.json(
        {
          error: "IOC required",
        },
        400,
      );
    }

    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);

    const data = isIP ? await getCensysHost(ioc) : await getCensysDomain(ioc);

    if (!data || data.error) {
      return c.json(
        {
          error: data?.error || "Censys lookup failed",
        },
        500,
      );
    }

    return c.json(data);
  } catch (error: any) {
    return c.json(
      {
        error: error.message || "Internal server error",
      },
      500,
    );
  }
});

export default censys;
