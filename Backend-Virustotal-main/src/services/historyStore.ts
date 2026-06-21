// src/services/historyStore.ts

import { supabase } from "./auth.js";

export interface HistoryEntry {
  reportId: string;
  userId: string;
  username: string;
  email: string;
  ioc: string;
  iocType: string;
  threatLevel: string;
  aiAnalysis: string;
  createdAt?: string;
}

export async function saveToHistory(entry: HistoryEntry): Promise<void> {
  const { error } = await supabase.from("report_history").insert({
    report_id: entry.reportId,
    user_id: entry.userId,
    username: entry.username,
    email: entry.email,
    ioc: entry.ioc,
    ioc_type: entry.iocType,
    threat_level: entry.threatLevel,
    ai_analysis: entry.aiAnalysis,
    created_at: entry.createdAt,
  });

  if (error) {
    throw error;
  }
}

export async function loadHistory(userId?: string): Promise<HistoryEntry[]> {
  let query = supabase.from("report_history").select("*").order("created_at", {
    ascending: false,
  });

  if (userId) {
    query = query.eq("user_id", userId);
  }

  const { data, error } = await query;

  if (error) {
    throw error;
  }

  return (data || []).map((row) => ({
    reportId: row.report_id,
    userId: row.user_id,

    username: row.username,
    email: row.email,

    ioc: row.ioc,
    iocType: row.ioc_type,

    threatLevel: row.threat_level,

    aiAnalysis: row.ai_analysis,

    createdAt: row.created_at,
  }));
}

export async function getReportById(
  reportId: string,
): Promise<HistoryEntry | null> {
  const { data, error } = await supabase
    .from("report_history")
    .select("*")
    .eq("report_id", reportId)
    .maybeSingle();

  if (error || !data) {
    return null;
  }

  return {
    reportId: data.report_id,
    userId: data.user_id,

    username: data.username,
    email: data.email,

    ioc: data.ioc,
    iocType: data.ioc_type,

    threatLevel: data.threat_level,

    aiAnalysis: data.ai_analysis,

    createdAt: data.created_at,
  };
}
