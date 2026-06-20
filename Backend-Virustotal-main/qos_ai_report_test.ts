import axios from "axios";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const BASE_URL = "http://localhost:5000";
const ENDPOINT = `${BASE_URL}/chat`;

// Isi token hanya kalau endpoint butuh login Supabase.
// Kalau tidak perlu login, biarkan kosong.
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";

type TestCase = {
  indicator: string;
  type: "ip" | "domain" | "url" | "file";
};

// Target pengujian QoS AI Report
const TARGET_INDICATOR = "45.155.205.233";
const TARGET_TYPE: TestCase["type"] = "ip";

// Jumlah pengulangan pengujian
const TOTAL_TEST = 3;

const testCases: TestCase[] = Array.from({ length: TOTAL_TEST }, () => ({
  indicator: TARGET_INDICATOR,
  type: TARGET_TYPE,
}));

const SECTION_MAP = {
  section_executive_summary: "EXECUTIVE SUMMARY",
  section_threat_overview: "THREAT OVERVIEW",
  section_vulnerability_analysis: "VULNERABILITY ANALYSIS",
  section_threat_intelligence_misp: "THREAT INTELLIGENCE",
  section_whois_intelligence: "WHOIS INTELLIGENCE",
  section_mitre_attack_analysis: "MITRE ATT&CK ANALYSIS",
  section_impact_analysis: "IMPACT ANALYSIS",
  section_mitigation_strategies: "MITIGATION STRATEGIES",
  section_course_of_action: "COURSE OF ACTION",
  section_conclusion: "CONCLUSION",
  section_references: "REFERENCES",
} as const;

type SectionKey = keyof typeof SECTION_MAP;

type SectionCheck = Record<SectionKey, boolean> & {
  all_sections_present: boolean;
  total_sections: number;
  found_sections: number;
  missing_sections: string;
};

type QoSResult = {
  no: number;
  indicator: string;
  type: string;
  status_code: number | string;
  success: boolean;

  report_id: string;
  severity: string;

  has_ai_report: boolean;
  has_vt_data: boolean;
  has_abuseipdb: boolean;
  has_misp_data: boolean;
  has_cve_matches: boolean;
  has_whois_data: boolean;

  section_executive_summary: boolean;
  section_threat_overview: boolean;
  section_vulnerability_analysis: boolean;
  section_threat_intelligence_misp: boolean;
  section_whois_intelligence: boolean;
  section_mitre_attack_analysis: boolean;
  section_impact_analysis: boolean;
  section_mitigation_strategies: boolean;
  section_course_of_action: boolean;
  section_conclusion: boolean;
  section_references: boolean;

  all_sections_present: boolean;
  total_sections: number;
  found_sections: number;
  missing_sections: string;

  report_length_chars: number;
  ai_report_file: string;

  response_time_seconds: number;
  error: string;
};

function getTimestamp() {
  return new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace("T", "_")
    .slice(0, 19);
}

function safeFileName(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}

function checkReportSections(aiReport: string): SectionCheck {
  const normalizedReport = aiReport.toUpperCase();

  const result = {} as Record<SectionKey, boolean>;

  for (const key of Object.keys(SECTION_MAP) as SectionKey[]) {
    result[key] = normalizedReport.includes(SECTION_MAP[key]);
  }

  const totalSections = Object.keys(SECTION_MAP).length;
  const foundSections = Object.values(result).filter(Boolean).length;

  const missingSections = (Object.keys(SECTION_MAP) as SectionKey[])
    .filter((key) => !result[key])
    .map((key) => SECTION_MAP[key]);

  return {
    ...result,
    all_sections_present: missingSections.length === 0,
    total_sections: totalSections,
    found_sections: foundSections,
    missing_sections: missingSections.join(" | "),
  };
}

function formatCSVValue(value: string | number | boolean | null | undefined) {
  const cleanValue = String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/"/g, '""');

  return `"${cleanValue}"`;
}

function toCSV(rows: QoSResult[]) {
  const delimiter = ";";

  const headers: (keyof QoSResult)[] = [
    "no",
    "indicator",
    "type",
    "status_code",
    "success",

    "report_id",
    "severity",

    "has_ai_report",
    "has_vt_data",
    "has_abuseipdb",
    "has_misp_data",
    "has_cve_matches",
    "has_whois_data",

    "section_executive_summary",
    "section_threat_overview",
    "section_vulnerability_analysis",
    "section_threat_intelligence_misp",
    "section_whois_intelligence",
    "section_mitre_attack_analysis",
    "section_impact_analysis",
    "section_mitigation_strategies",
    "section_course_of_action",
    "section_conclusion",
    "section_references",

    "all_sections_present",
    "total_sections",
    "found_sections",
    "missing_sections",

    "report_length_chars",
    "ai_report_file",

    "response_time_seconds",
    "error",
  ];

  const csvRows = [
    "sep=;",
    headers.join(delimiter),
    ...rows.map((row) =>
      headers.map((header) => formatCSVValue(row[header])).join(delimiter),
    ),
  ];

  return "\uFEFF" + csvRows.join("\r\n");
}

function createFailedSectionCheck(): SectionCheck {
  const emptySections = {} as Record<SectionKey, boolean>;

  for (const key of Object.keys(SECTION_MAP) as SectionKey[]) {
    emptySections[key] = false;
  }

  return {
    ...emptySections,
    all_sections_present: false,
    total_sections: Object.keys(SECTION_MAP).length,
    found_sections: 0,
    missing_sections: Object.values(SECTION_MAP).join(" | "),
  };
}

async function runQoSTest() {
  const results: QoSResult[] = [];

  const runTimestamp = getTimestamp();
  const reportFolder = `qos_ai_reports_${runTimestamp}`;

  mkdirSync(reportFolder, { recursive: true });

  for (const [index, item] of testCases.entries()) {
    const no = index + 1;
    const start = Date.now();

    try {
      const response = await axios.post(
        ENDPOINT,
        {
          indicator: item.indicator,
          type: item.type,
          username: "QoS Test",
          email: "qos@test.local",
        },
        {
          timeout: 180000,
          headers: TOKEN
            ? {
                Authorization: `Bearer ${TOKEN}`,
              }
            : {},
        },
      );

      const end = Date.now();
      const responseTime = (end - start) / 1000;

      const aiReport = String(response.data?.aiAnalysis || "");
      const sectionCheck = checkReportSections(aiReport);

      const reportFileName = `ai_report_${no}_${safeFileName(
        item.indicator,
      )}.md`;

      const reportFilePath = join(reportFolder, reportFileName);

      if (aiReport) {
        writeFileSync(reportFilePath, aiReport, "utf-8");
      }

      results.push({
        no,
        indicator: item.indicator,
        type: item.type,
        status_code: response.status,
        success: response.data?.success === true,

        report_id: response.data?.reportId || "",
        severity: response.data?.severity || "",

        has_ai_report: Boolean(aiReport),
        has_vt_data: Boolean(response.data?.vtData),
        has_abuseipdb: Boolean(response.data?.abuseipdb),
        has_misp_data: Boolean(response.data?.mispData),
        has_cve_matches:
          Array.isArray(response.data?.cveMatches) &&
          response.data.cveMatches.length > 0,
        has_whois_data: Boolean(response.data?.whoisData),

        ...sectionCheck,

        report_length_chars: aiReport.length,
        ai_report_file: aiReport ? reportFilePath : "",

        response_time_seconds: Number(responseTime.toFixed(2)),
        error: "",
      });

      console.log(
        `[OK] Full AI Report ${no} - ${item.indicator} (${item.type}) - ${responseTime.toFixed(
          2,
        )} detik`,
      );
    } catch (error: unknown) {
      const end = Date.now();
      const responseTime = (end - start) / 1000;

      let statusCode: number | string = "ERROR";
      let errorMessage = "Unknown error";

      if (axios.isAxiosError(error)) {
        statusCode = error.response?.status || "ERROR";
        errorMessage =
          error.response?.data?.error ||
          error.response?.data?.message ||
          error.message;
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }

      const failedSections = createFailedSectionCheck();

      results.push({
        no,
        indicator: item.indicator,
        type: item.type,
        status_code: statusCode,
        success: false,

        report_id: "",
        severity: "",

        has_ai_report: false,
        has_vt_data: false,
        has_abuseipdb: false,
        has_misp_data: false,
        has_cve_matches: false,
        has_whois_data: false,

        ...failedSections,

        report_length_chars: 0,
        ai_report_file: "",

        response_time_seconds: Number(responseTime.toFixed(2)),
        error: errorMessage,
      });

      console.log(
        `[ERROR] Full AI Report ${no} - ${item.indicator} (${item.type}) - ${responseTime.toFixed(
          2,
        )} detik`,
      );
    }
  }

  const totalTests = results.length;
  const successCount = results.filter((r) => r.success).length;
  const failedCount = totalTests - successCount;

  const avgResponseTime =
    totalTests > 0
      ? results.reduce((sum, r) => sum + r.response_time_seconds, 0) /
        totalTests
      : 0;

  const successRate = totalTests > 0 ? (successCount / totalTests) * 100 : 0;
  const errorRate = totalTests > 0 ? (failedCount / totalTests) * 100 : 0;

  const completeReportCount = results.filter(
    (r) => r.has_ai_report && r.all_sections_present,
  ).length;

  const completeReportRate =
    totalTests > 0 ? (completeReportCount / totalTests) * 100 : 0;

  console.log("\n===== FULL AI REPORT QOS SUMMARY =====");
  console.log(`Indicator                 : ${TARGET_INDICATOR}`);
  console.log(`Type                      : ${TARGET_TYPE}`);
  console.log(`Total Test                : ${totalTests}`);
  console.log(`Success                   : ${successCount}`);
  console.log(`Failed                    : ${failedCount}`);
  console.log(`Success Rate              : ${successRate.toFixed(2)}%`);
  console.log(`Error Rate                : ${errorRate.toFixed(2)}%`);
  console.log(`Complete AI Report        : ${completeReportCount}`);
  console.log(`Complete AI Report Rate   : ${completeReportRate.toFixed(2)}%`);
  console.log(
    `Avg Response Time         : ${avgResponseTime.toFixed(2)} detik`,
  );

  const csvFileName = `qos_full_ai_report_result_${runTimestamp}.csv`;
  const jsonFileName = `qos_full_ai_report_summary_${runTimestamp}.json`;

  writeFileSync(csvFileName, toCSV(results), "utf-8");

  writeFileSync(
    jsonFileName,
    JSON.stringify(
      {
        indicator: TARGET_INDICATOR,
        type: TARGET_TYPE,
        total_tests: totalTests,
        success_count: successCount,
        failed_count: failedCount,
        success_rate: Number(successRate.toFixed(2)),
        error_rate: Number(errorRate.toFixed(2)),
        complete_report_count: completeReportCount,
        complete_report_rate: Number(completeReportRate.toFixed(2)),
        average_response_time_seconds: Number(avgResponseTime.toFixed(2)),
        report_folder: reportFolder,
        results,
      },
      null,
      2,
    ),
    "utf-8",
  );

  console.log("\nHasil disimpan ke:");
  console.log(`- ${csvFileName}`);
  console.log(`- ${jsonFileName}`);
  console.log(`- Folder report lengkap: ${reportFolder}`);
}

runQoSTest();
