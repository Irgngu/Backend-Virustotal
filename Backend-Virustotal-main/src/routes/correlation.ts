// import { Hono } from "hono";
// import { getCensysHost, getCensysDomain } from "../services/censys.js";
// import { extractProducts } from "../core/correlation.js";

// const correlation = new Hono();

// correlation.get("/:ioc", async (c) => {
//   try {
//     const ioc = c.req.param("ioc");

//     const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);

//     // ===============================
//     // CENSYS LOOKUP
//     // ===============================
//     const censysData = isIP
//       ? await getCensysHost(ioc)
//       : await getCensysDomain(ioc);

//     // ===============================
//     // EXTRACT PRODUCTS
//     // ===============================
//     const products = extractProducts(censysData);

//     // ===============================
//     // LOAD KEV ONCE
//     // ===============================
//     const kevRes = await fetch(
//       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
//     );

//     const kevJson = await kevRes.json();
//     const kevList = kevJson.vulnerabilities || [];

//     const results = [];

//     // ===============================
//     // LOOP PRODUCTS
//     // ===============================
//     for (const item of products) {
//       const keyword = `${item.product} ${item.version}`.trim();

//       const nvdRes = await fetch(
//         `http://localhost:${process.env.PORT || 5000}/api/nvd?keyword=${encodeURIComponent(keyword)}`,
//       );

//       const nvdData = await nvdRes.json();

//       const vulnerabilities = nvdData.vulnerabilities || [];

//       const mapped = vulnerabilities.map((v: any) => {
//         const id = v.cve?.id;

//         const kevFound = kevList.find((k: any) => k.cveID === id);

//         return {
//           cve: id,
//           exploited: !!kevFound,
//           dueDate: kevFound?.dueDate || null,
//         };
//       });

//       results.push({
//         vendor: item.vendor,
//         product: item.product,
//         version: item.version,
//         port: item.port,
//         cves: mapped,
//       });
//     }

//     return c.json({
//       success: true,
//       target: ioc,
//       totalProducts: results.length,
//       products: results,
//     });
//   } catch (error: any) {
//     return c.json(
//       {
//         success: false,
//         error: error.message,
//       },
//       500,
//     );
//   }
// });

// export default correlation;
