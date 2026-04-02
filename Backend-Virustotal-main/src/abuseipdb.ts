import axios from "axios"


/* ===============================
   🔍 CHECK IP FROM ABUSEIPDB
================================ */
export async function checkIP(ip: string) {
    const ABUSE_API_KEY = process.env.ABUSE_API_KEY as string
  try {
    const res = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      headers: {
        Key: ABUSE_API_KEY,
        Accept: "application/json"
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: true
      }
    })

    return res.data

  } catch (error) {
    console.error("AbuseIPDB Error:", error)
    return null
  }
}


/* ===============================
   🌍 FALLBACK GEOLOCATION
================================ */
export async function getLocationFallback(ip: string) {
  try {
    const res = await axios.get(`https://ipinfo.io/${ip}/json`)
    return res.data
  } catch (error) {
    console.error("Fallback Error:", error)
    return null
  }
}