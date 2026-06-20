import axios from "axios";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";

const BASE_URL = "http://localhost:5000";

// Token hanya dipakai kalau endpoint butuh login Supabase.
// Kalau tidak perlu login, biarkan kosong.
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";

// Target utama pengujian QoS
const TARGET_INDICATOR = "45.155.205.233";
const TARGET_TYPE = "ip";

const SAMPLE_REPORT_CONTENT = `
THREAT INTELLIGENCE REPORT

EXECUTIVE SUMMARY
This is a QoS export test report.

THREAT OVERVIEW
Indicator: 45.155.205.233
Type: IP Address

VULNERABILITY ANALYSIS
No CVE correlation found in this sample export content.

THREAT INTELLIGENCE (MISP)
No MISP correlation found in this sample export content.

MITRE ATT&CK ANALYSIS
No MITRE ATT&CK data available in this sample export content.

IMPACT ANALYSIS
This sample content is used only for testing export performance.

MITIGATION STRATEGIES
Block indicator and monitor related traffic.

COURSE OF ACTION
- Block indicator
- Monitor related traffic
- Review affected product versions

CONCLUSION
This report is generated for QoS testing only.

REFERENCES
- VirusTotal
- AbuseIPDB
- MISP
- MITRE ATT&CK
`;

type HttpMethod = "GET" | "POST";

type FeatureTest = {
  feature: string;
  method: HttpMethod;
  endpoint: string;
  body?: any;
  timeoutMs?: number;
  responseType?: "json" | "arraybuffer";
  saveAs?: string;
  validate: (
    data: any,
    statusCode: number,
    headers: any,
  ) => {
    success: boolean;
    notes: string;
  };
};

type QoSFeatureResult = {
  no: number;
  feature: string;
  method: string;
  endpoint: string;
  status_code: number | string;
  success: boolean;
  response_time_seconds: number;
  response_size_bytes: number;
  saved_file: string;
  notes: string;
  error: string;
};

type LocalHistoryEntry = {
  reportId: string;
  userId?: string;
  username: string;
  email: string;
  ioc: string;
  iocType: string;
  threatLevel: string;
  aiAnalysis: string;
  createdAt: string;
};

function getTimestamp() {
  return new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace("T", "_")
    .slice(0, 19);
}

function formatCSVValue(value: string | number | boolean | null | undefined) {
  const cleanValue = String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/"/g, '""');

  return `"${cleanValue}"`;
}

function toCSV(rows: QoSFeatureResult[]) {
  const delimiter = ";";

  const headers: (keyof QoSFeatureResult)[] = [
    "no",
    "feature",
    "method",
    "endpoint",
    "status_code",
    "success",
    "response_time_seconds",
    "response_size_bytes",
    "saved_file",
    "notes",
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

function getResponseSize(data: any): number {
  if (Buffer.isBuffer(data)) {
    return data.length;
  }

  if (data instanceof ArrayBuffer) {
    return data.byteLength;
  }

  if (typeof data === "string") {
    return Buffer.byteLength(data, "utf-8");
  }

  return Buffer.byteLength(JSON.stringify(data ?? ""), "utf-8");
}

function getErrorMessage(error: unknown): {
  statusCode: number | string;
  message: string;
} {
  if (axios.isAxiosError(error)) {
    let message = error.message;

    const data = error.response?.data;

    if (data) {
      if (Buffer.isBuffer(data)) {
        message = data.toString("utf-8");
      } else if (typeof data === "object") {
        message = data.error || data.message || JSON.stringify(data);
      } else {
        message = String(data);
      }
    }

    return {
      statusCode: error.response?.status || "ERROR",
      message,
    };
  }

  if (error instanceof Error) {
    return {
      statusCode: "ERROR",
      message: error.message,
    };
  }

  return {
    statusCode: "ERROR",
    message: "Unknown error",
  };
}

function checkHistoryStore(reportId: string) {
  const historyPath = join(process.cwd(), "data", "history.json");

  if (!reportId) {
    return {
      success: false,
      savedFile: historyPath,
      notes: "Report ID not found from /chat response",
    };
  }

  if (!existsSync(historyPath)) {
    return {
      success: false,
      savedFile: historyPath,
      notes: "data/history.json not found",
    };
  }

  try {
    const raw = readFileSync(historyPath, "utf-8");
    const history = JSON.parse(raw) as LocalHistoryEntry[];

    const entry = history.find((item) => item.reportId === reportId);

    if (!entry) {
      return {
        success: false,
        savedFile: historyPath,
        notes: `Report ID ${reportId} not found in history.json`,
      };
    }

    return {
      success: true,
      savedFile: historyPath,
      notes:
        `History saved successfully; ` +
        `reportId: ${entry.reportId}; ` +
        `ioc: ${entry.ioc}; ` +
        `type: ${entry.iocType}; ` +
        `threatLevel: ${entry.threatLevel}; ` +
        `createdAt: ${entry.createdAt}`,
    };
  } catch (error) {
    return {
      success: false,
      savedFile: historyPath,
      notes:
        error instanceof Error
          ? `Failed to read history.json: ${error.message}`
          : "Failed to read history.json",
    };
  }
}

const featureTests: FeatureTest[] = [
  {
    feature: "Health Check API",
    method: "GET",
    endpoint: "/",
    timeoutMs: 30000,
    validate: (data, statusCode) => ({
      success: statusCode === 200,
      notes: typeof data === "string" ? data : "Health check tested",
    }),
  },

  {
    feature: "AI Generated Report",
    method: "POST",
    endpoint: "/chat",
    timeoutMs: 180000,
    body: {
      indicator: TARGET_INDICATOR,
      type: TARGET_TYPE,
      username: "QoS Test",
      email: "qos@test.local",
    },
    validate: (data, statusCode) => {
      const aiReport = String(data?.aiAnalysis || "");

      return {
        success:
          statusCode === 200 && data?.success === true && aiReport.length > 0,
        notes: aiReport
          ? `AI report generated; reportId: ${
              data?.reportId || "-"
            }; length: ${aiReport.length} chars`
          : "AI report not found",
      };
    },
  },

  {
    feature: "VirusTotal Analyze",
    method: "POST",
    endpoint: "/api/analyze",
    timeoutMs: 120000,
    body: {
      indicator: TARGET_INDICATOR,
      type: TARGET_TYPE,
    },
    validate: (data, statusCode) => ({
      success: statusCode === 200 && Boolean(data?.indicator),
      notes: data?.indicator
        ? `VirusTotal data found for ${data.indicator}; threatLevel: ${
            data.threatLevel || "-"
          }`
        : "VirusTotal response missing indicator",
    }),
  },

  {
    feature: "IP Reputation / AbuseIPDB",
    method: "POST",
    endpoint: "/check-ip",
    timeoutMs: 120000,
    body: {
      ip: TARGET_INDICATOR,
    },
    validate: (data, statusCode) => ({
      success: statusCode === 200 && data?.score !== undefined,
      notes:
        data?.score !== undefined
          ? `Abuse score: ${data.score}; reports: ${
              data.reports ?? "-"
            }; status: ${data.status ?? "-"}`
          : "AbuseIPDB score not found",
    }),
  },

  {
    feature: "MISP Search",
    method: "POST",
    endpoint: "/misp/search",
    timeoutMs: 120000,
    body: {
      indicator: TARGET_INDICATOR,
    },
    validate: (data, statusCode) => ({
      success: statusCode === 200 && data?.success === true,
      notes: data?.mispData
        ? `MISP match count: ${data.mispData.matchCount ?? 0}; ` +
          `threat level: ${data.mispData.threatLevel ?? "-"}; ` +
          `event title: ${data.mispData.title ?? "-"}`
        : "MISP data not found",
    }),
  },

  {
    feature: "NVD CVE Search",
    method: "GET",
    endpoint: "/api/nvd?keyword=apache",
    timeoutMs: 120000,
    validate: (data, statusCode) => ({
      success: statusCode === 200 && Array.isArray(data?.results),
      notes: Array.isArray(data?.results)
        ? `NVD results: ${data.results.length}; totalResults: ${
            data.totalResults ?? "-"
          }`
        : "NVD results not found",
    }),
  },

  {
    feature: "Export PDF",
    method: "POST",
    endpoint: "/api/export",
    timeoutMs: 120000,
    responseType: "arraybuffer",
    saveAs: "qos_export_test.pdf",
    body: {
      content: SAMPLE_REPORT_CONTENT,
      format: "pdf",
    },
    validate: (_data, statusCode, headers) => {
      const contentType = String(headers["content-type"] || "");

      return {
        success: statusCode === 200 && contentType.includes("application/pdf"),
        notes: `Content-Type: ${contentType}`,
      };
    },
  },

  {
    feature: "Export DOCX",
    method: "POST",
    endpoint: "/api/export",
    timeoutMs: 120000,
    responseType: "arraybuffer",
    saveAs: "qos_export_test.docx",
    body: {
      content: SAMPLE_REPORT_CONTENT,
      format: "docx",
    },
    validate: (_data, statusCode, headers) => {
      const contentType = String(headers["content-type"] || "");

      return {
        success:
          statusCode === 200 &&
          contentType.includes(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          ),
        notes: `Content-Type: ${contentType}`,
      };
    },
  },

  {
    feature: "Export STIX 2.1",
    method: "POST",
    endpoint: "/export/stix",
    timeoutMs: 120000,
    body: {
      reportId: "QOS-STIX-TEST",
      indicator: TARGET_INDICATOR,
      type: TARGET_TYPE,
      threatLevel: "Low",
      aiAnalysis: SAMPLE_REPORT_CONTENT,
    },
    validate: (data, statusCode) => ({
      success: statusCode === 200 && Boolean(data?.type),
      notes: data?.type
        ? `STIX response type: ${data.type}`
        : "STIX response type not found",
    }),
  },
];

// History API hanya diuji kalau token Supabase tersedia.
if (TOKEN) {
  featureTests.push({
    feature: "History API",
    method: "GET",
    endpoint: "/history",
    timeoutMs: 120000,
    validate: (data, statusCode) => ({
      success: statusCode === 200 && data?.success === true,
      notes: Array.isArray(data?.history)
        ? `History count: ${data.history.length}; role: ${data.role || "-"}`
        : "History not found",
    }),
  });
}

function pushFailedDerivedRows(params: {
  results: QoSFeatureResult[];
  rowNoRef: { value: number };
  responseTime: number;
  statusCode: number | string;
  errorMessage: string;
}) {
  const derivedFeatures = [
    "Threat Correlation Engine",
    "MITRE ATT&CK Mapping",
    "History Store",
  ];

  for (const feature of derivedFeatures) {
    params.results.push({
      no: params.rowNoRef.value++,
      feature,
      method: "POST",
      endpoint: "/chat",
      status_code: params.statusCode,
      success: false,
      response_time_seconds: Number(params.responseTime.toFixed(2)),
      response_size_bytes: 0,
      saved_file: "",
      notes: "",
      error: `Skipped because AI Generated Report failed: ${params.errorMessage}`,
    });
  }
}

async function runAllFeatureQoSTest() {
  const results: QoSFeatureResult[] = [];
  const runTimestamp = getTimestamp();

  const outputFolder = `qos_all_features_${runTimestamp}`;
  mkdirSync(outputFolder, { recursive: true });

  const rowNoRef = { value: 1 };

  for (const test of featureTests) {
    const no = rowNoRef.value++;
    const start = Date.now();

    try {
      const axiosConfig: any = {
        method: test.method,
        url: `${BASE_URL}${test.endpoint}`,
        data: test.body,
        timeout: test.timeoutMs ?? 120000,
        validateStatus: () => true,
        headers: TOKEN
          ? {
              Authorization: `Bearer ${TOKEN}`,
            }
          : {},
      };

      if (test.responseType === "arraybuffer") {
        axiosConfig.responseType = "arraybuffer";
      }

      const response = await axios.request(axiosConfig);

      const end = Date.now();
      const responseTime = (end - start) / 1000;
      const responseSize = getResponseSize(response.data);

      const validation = test.validate(
        response.data,
        response.status,
        response.headers,
      );

      let savedFile = "";

      if (test.saveAs) {
        savedFile = join(outputFolder, test.saveAs);

        const fileBuffer = Buffer.isBuffer(response.data)
          ? response.data
          : Buffer.from(response.data);

        writeFileSync(savedFile, fileBuffer);
      }

      if (
        test.feature === "AI Generated Report" &&
        typeof response.data?.aiAnalysis === "string"
      ) {
        savedFile = join(outputFolder, "qos_ai_generated_report.md");
        writeFileSync(savedFile, response.data.aiAnalysis, "utf-8");
      }

      results.push({
        no,
        feature: test.feature,
        method: test.method,
        endpoint: test.endpoint,
        status_code: response.status,
        success: validation.success,
        response_time_seconds: Number(responseTime.toFixed(2)),
        response_size_bytes: responseSize,
        saved_file: savedFile,
        notes: validation.notes,
        error: validation.success ? "" : "Validation failed",
      });

      if (test.feature === "AI Generated Report") {
        const chatData = response.data;
        const aiReport = String(chatData?.aiAnalysis || "");
        const upperReport = aiReport.toUpperCase();

        // =====================================================
        // 1. THREAT CORRELATION ENGINE
        // =====================================================
        const correlationInsights = String(chatData?.correlationInsights || "");
        const upperCorrelation = correlationInsights.toUpperCase();

        const hasCorrelationInsights = correlationInsights.length > 0;
        const hasWeightProfile = upperCorrelation.includes(
          "WEIGHT PROFILE APPLIED",
        );
        const hasWeightedScore = upperCorrelation.includes(
          "WEIGHTED CONFIDENCE SCORE",
        );
        const hasVirusTotalAnalysis = upperCorrelation.includes("VIRUSTOTAL");
        const hasAbuseIPDBAnalysis = upperCorrelation.includes("ABUSEIPDB");
        const hasMISPAnalysis = upperCorrelation.includes("MISP");
        const hasCVEAnalysis = upperCorrelation.includes("CVE");
        const hasFinalAssessment =
          upperCorrelation.includes("OVERALL ASSESSMENT");

        const correlationPassed =
          hasCorrelationInsights &&
          hasWeightProfile &&
          hasWeightedScore &&
          hasFinalAssessment;

        results.push({
          no: rowNoRef.value++,
          feature: "Threat Correlation Engine",
          method: test.method,
          endpoint: test.endpoint,
          status_code: response.status,
          success: response.status === 200 && correlationPassed,
          response_time_seconds: Number(responseTime.toFixed(2)),
          response_size_bytes: responseSize,
          saved_file: savedFile,
          notes:
            `correlationInsights: ${hasCorrelationInsights}; ` +
            `weight profile: ${hasWeightProfile}; ` +
            `weighted score: ${hasWeightedScore}; ` +
            `VirusTotal analysis: ${hasVirusTotalAnalysis}; ` +
            `AbuseIPDB analysis: ${hasAbuseIPDBAnalysis}; ` +
            `MISP analysis: ${hasMISPAnalysis}; ` +
            `CVE analysis: ${hasCVEAnalysis}; ` +
            `final assessment: ${hasFinalAssessment}`,
          error:
            response.status === 200 && correlationPassed
              ? ""
              : "Threat Correlation Engine output incomplete",
        });

        // =====================================================
        // 2. MITRE ATT&CK MAPPING
        // =====================================================
        const mitreTechniqueCount = Array.isArray(chatData?.mitreTechniques)
          ? chatData.mitreTechniques.length
          : 0;

        const mitreMitigationCount = Array.isArray(chatData?.mitreMitigations)
          ? chatData.mitreMitigations.length
          : 0;

        const hasMitreSection =
          upperReport.includes("MITRE ATT&CK") ||
          upperReport.includes("MITRE ATTACK") ||
          upperReport.includes("ATT&CK ANALYSIS");

        const hasMitreData =
          hasMitreSection ||
          mitreTechniqueCount > 0 ||
          mitreMitigationCount > 0;

        results.push({
          no: rowNoRef.value++,
          feature: "MITRE ATT&CK Mapping",
          method: test.method,
          endpoint: test.endpoint,
          status_code: response.status,
          success: response.status === 200 && hasMitreData,
          response_time_seconds: Number(responseTime.toFixed(2)),
          response_size_bytes: responseSize,
          saved_file: savedFile,
          notes:
            `MITRE section: ${hasMitreSection}; ` +
            `techniques: ${mitreTechniqueCount}; ` +
            `mitigations: ${mitreMitigationCount}; ` +
            `technique name: ${chatData?.mitreTechniqueName || "-"}`,
          error:
            response.status === 200 && hasMitreData
              ? ""
              : "MITRE ATT&CK data not found in /chat response",
        });

        // =====================================================
        // 3. HISTORY STORE
        // =====================================================
        const historyCheck = checkHistoryStore(
          String(chatData?.reportId || ""),
        );

        results.push({
          no: rowNoRef.value++,
          feature: "History Store",
          method: test.method,
          endpoint: "/chat -> data/history.json",
          status_code: response.status,
          success: response.status === 200 && historyCheck.success,
          response_time_seconds: Number(responseTime.toFixed(2)),
          response_size_bytes: responseSize,
          saved_file: historyCheck.savedFile,
          notes: historyCheck.notes,
          error:
            response.status === 200 && historyCheck.success
              ? ""
              : "History Store failed or report not found in history.json",
        });
      }

      const label = validation.success ? "OK" : "FAILED";

      console.log(
        `[${label}] ${test.feature} - ${responseTime.toFixed(2)} detik`,
      );
    } catch (error: unknown) {
      const end = Date.now();
      const responseTime = (end - start) / 1000;

      const err = getErrorMessage(error);

      results.push({
        no,
        feature: test.feature,
        method: test.method,
        endpoint: test.endpoint,
        status_code: err.statusCode,
        success: false,
        response_time_seconds: Number(responseTime.toFixed(2)),
        response_size_bytes: 0,
        saved_file: "",
        notes: "",
        error: err.message,
      });

      if (test.feature === "AI Generated Report") {
        pushFailedDerivedRows({
          results,
          rowNoRef,
          responseTime,
          statusCode: err.statusCode,
          errorMessage: err.message,
        });
      }

      console.log(`[ERROR] ${test.feature} - ${responseTime.toFixed(2)} detik`);
    }
  }

  const totalTests = results.length;
  const successCount = results.filter((r) => r.success).length;
  const failedCount = totalTests - successCount;

  const successRate = totalTests > 0 ? (successCount / totalTests) * 100 : 0;
  const errorRate = totalTests > 0 ? (failedCount / totalTests) * 100 : 0;

  const avgResponseTime =
    totalTests > 0
      ? results.reduce((sum, r) => sum + r.response_time_seconds, 0) /
        totalTests
      : 0;

  const csvFileName = `qos_all_features_result_${runTimestamp}.csv`;
  const jsonFileName = `qos_all_features_summary_${runTimestamp}.json`;

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
        average_response_time_seconds: Number(avgResponseTime.toFixed(2)),
        output_folder: outputFolder,
        results,
      },
      null,
      2,
    ),
    "utf-8",
  );

  console.log("\n===== ALL FEATURES QOS SUMMARY =====");
  console.log(`Indicator         : ${TARGET_INDICATOR}`);
  console.log(`Type              : ${TARGET_TYPE}`);
  console.log(`Total Test        : ${totalTests}`);
  console.log(`Success           : ${successCount}`);
  console.log(`Failed            : ${failedCount}`);
  console.log(`Success Rate      : ${successRate.toFixed(2)}%`);
  console.log(`Error Rate        : ${errorRate.toFixed(2)}%`);
  console.log(`Avg Response Time : ${avgResponseTime.toFixed(2)} detik`);

  console.log("\nHasil disimpan ke:");
  console.log(`- ${csvFileName}`);
  console.log(`- ${jsonFileName}`);
  console.log(`- Folder output: ${outputFolder}`);
}

runAllFeatureQoSTest();
