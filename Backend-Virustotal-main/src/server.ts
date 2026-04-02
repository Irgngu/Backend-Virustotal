import dotenv from "dotenv"
import { Hono } from "hono"
import { serve } from "@hono/node-server"
import net from "net"

import { fetchVirusTotal } from "./virustotal.js"
import { checkIP, getLocationFallback } from "./abuseipdb.js"

dotenv.config()

const app = new Hono()

/* ===============================
   🌐 ROOT
================================ */
app.get("/", (c) => {
  return c.text("Backend Threat Intelligence API running")
})


/* ===============================
   🔬 VIRUSTOTAL ANALYSIS
================================ */
app.post("/api/analyze", async (c) => {
  try {
    const body = await c.req.json()
    const { indicator, type } = body

    if (!indicator || !type) {
      return c.json({
        error: "indicator dan type diperlukan"
      }, 400)
    }

    const data = await fetchVirusTotal(indicator, type)

    return c.json(data)

  } catch (error) {
    console.error(error)

    return c.json({
      error: "Failed to fetch VirusTotal data"
    }, 500)
  }
})


/* ===============================
   🛡 CHECK IP (ABUSEIPDB)
================================ */
app.post("/check-ip", async (c) => {
  try {
    const body = await c.req.json()
    const ip = body.ip

    if (!ip) {
      return c.json({ error: "IP address diperlukan" }, 400)
    }

    if (!net.isIP(ip)) {
      return c.json({ error: "Format IP tidak valid" }, 400)
    }

    const dataAPI = await checkIP(ip)

    if (!dataAPI || !dataAPI.data) {
      return c.json({ error: "Gagal mengambil data dari AbuseIPDB" }, 500)
    }

    const api = dataAPI.data
    const fallback = await getLocationFallback(ip)

    const score = api.abuseConfidenceScore || 0
    const reports = api.totalReports || 0

    const country = api.countryCode || fallback?.country
    const city = api.city || fallback?.city
    const asn = api.asn || fallback?.org

    let status = "Aman"

    if (score > 50) {
      status = "Berbahaya"
    } else if (score > 10) {
      status = "Mencurigakan"
    }

    const result = {
      ip,
      score,
      reports,
      status,
      country: country || "-",
      city: city || "-",
      isp: api.isp || fallback?.org || "-",
      usage_type: api.usageType || "-",
      domain: api.domain || "-",
      asn: asn || "Unknown"
    }

    return c.json(result)

  } catch (error) {
    console.error(error)

    return c.json({
      error: "Failed to check IP reputation"
    }, 500)
  }
})


/* ===============================
   🚀 SERVER START
================================ */
const PORT = Number(process.env.PORT) || 5000

serve({
  fetch: app.fetch,
  port: PORT
})

console.log(`Server running on http://localhost:${PORT}`)