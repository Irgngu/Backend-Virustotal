import axios from "axios";

const client = axios.create({
  baseURL: "https://api.platform.censys.io/v3",
  headers: {
    Authorization: `Bearer ${process.env.CENSYS_PAT}`,
    Accept: "application/json",
    "Content-Type": "application/json",
  },
});

/* =========================================
   GET HOST DATA (IOC IP)
========================================= */
export async function getCensysHost(ip: string) {
  try {
    const res = await client.get(`/global/asset/host/${ip}`);

    return res.data?.result?.resource || null;
  } catch (err: any) {
    console.log(
      "Censys Host Error:",
      err?.response?.status,
      err?.response?.data || err.message,
    );

    return null;
  }
}

/* =========================================
   GET DOMAIN / WEB PROPERTY DATA
========================================= */
export async function getCensysDomain(domain: string) {
  try {
    const res = await client.get(
      `/global/asset/web-property/${encodeURIComponent(domain)}`,
    );

    return res.data?.result?.resource || null;
  } catch (err: any) {
    console.log(
      "Censys Domain Error:",
      err?.response?.status,
      err?.response?.data || err.message,
    );

    return null;
  }
}
