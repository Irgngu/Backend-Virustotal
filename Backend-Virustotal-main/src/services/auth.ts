import dotenv from "dotenv";
dotenv.config();

import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl) {
  throw new Error("Missing SUPABASE_URL in backend .env");
}

if (!supabaseServiceRoleKey) {
  throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY in backend .env");
}

export const supabase = createClient(
  supabaseUrl,
  supabaseServiceRoleKey,
);

export async function getAuthUser(c: any) {
  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return {
      user: null,
      profile: null,
      error: "Missing Authorization token",
    };
  }

  const token = authHeader.replace("Bearer ", "");

  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser(token);

  if (userError || !user) {
    return {
      user: null,
      profile: null,
      error: "Invalid token",
    };
  }

  const { data: profile, error: profileError } = await supabase
    .from("profiles")
    .select("id, email, name, role")
    .eq("id", user.id)
    .maybeSingle();

  if (profileError) {
    return {
      user,
      profile: null,
      error: profileError.message,
    };
  }

  return {
    user,
    profile,
    error: null,
  };
}