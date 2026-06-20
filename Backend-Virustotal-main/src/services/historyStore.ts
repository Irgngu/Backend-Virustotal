import fs from "fs";
import path from "path";

const DATA_DIR = path.join(process.cwd(), "data");
const HISTORY_FILE = path.join(DATA_DIR, "history.json");

export interface HistoryEntry {
  reportId: string;
  userId?: string;
  username: string;
  email: string;
  ioc: string;
  iocType: string;
  threatLevel: string;
  aiAnalysis: string;
  createdAt: string; // ISO string
}

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

export function loadHistory(): HistoryEntry[] {
  ensureDataDir();
  if (!fs.existsSync(HISTORY_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(HISTORY_FILE, "utf-8")) as HistoryEntry[];
  } catch {
    return [];
  }
}

export function saveToHistory(entry: HistoryEntry): void {
  ensureDataDir();
  const history = loadHistory();
  history.unshift(entry); // newest first
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2), "utf-8");
}

export function getReportById(reportId: string): HistoryEntry | null {
  const history = loadHistory();
  return history.find((e) => e.reportId === reportId) ?? null;
}
