const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env"), override: true });
const { createClient } = require("@supabase/supabase-js");

const fallbackUrl = "https://nrxpikexvujleglfnvle.supabase.co";
const fallbackAnonKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5yeHBpa2V4dnVqbGVnbGZudmxlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA0OTAyNDAsImV4cCI6MjA4NjA2NjI0MH0.IYkXnM8xepEjHMKYto33gC5TspOOeNsAyX_BEu4qZXw";

const supabaseUrl = process.env.SUPABASE_URL || fallbackUrl;

// Public client: for reads only (respects RLS)
const publicKey = process.env.SUPABASE_ANON_KEY || fallbackAnonKey;
const supabasePublic = createClient(supabaseUrl, publicKey, {
  auth: { persistSession: false },
});

// Admin client: for inserts/uploads (bypasses RLS). MUST be server-side only.
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const supabaseAdmin = serviceKey
  ? createClient(supabaseUrl, serviceKey, { auth: { persistSession: false } })
  : null;

if (!serviceKey) {
  console.warn(
    "[supabase] SUPABASE_SERVICE_ROLE_KEY missing (admin writes/uploads disabled)."
  );
}

module.exports = { supabasePublic, supabaseAdmin };
