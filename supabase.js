require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const supabaseUrl =
	process.env.SUPABASE_URL || "https://nrxpikexvujleglfnvle.supabase.co";

// For DB reads/writes (products table), anon key can work if your RLS allows it.
// For Storage uploads from server, you should use SERVICE ROLE key.
const supabaseKey =
	process.env.SUPABASE_SERVICE_ROLE_KEY ||
	process.env.SUPABASE_ANON_KEY ||
	// Fallback for beginners (but you should move this to backend/.env and rotate keys)
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5yeHBpa2V4dnVqbGVnbGZudmxlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA0OTAyNDAsImV4cCI6MjA4NjA2NjI0MH0.IYkXnM8xepEjHMKYto33gC5TspOOeNsAyX_BEu4qZXw";

if (!process.env.SUPABASE_SERVICE_ROLE_KEY && !process.env.SUPABASE_ANON_KEY) {
	console.warn(
		"[supabase] Using fallback key. Create backend/.env (see backend/.env.example) and rotate keys in Supabase for security."
	);
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;
