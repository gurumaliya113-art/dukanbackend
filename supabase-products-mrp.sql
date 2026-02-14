-- Add MRP fields so you can show: Price + struck-through MRP + 50% OFF
-- Run this in Supabase SQL Editor.

alter table public.products
  add column if not exists mrp_inr numeric,
  add column if not exists mrp_usd numeric;

-- Optional: basic sanity checks (comment out if you prefer no constraints)
-- alter table public.products
--   add constraint products_mrp_inr_nonneg check (mrp_inr is null or mrp_inr >= 0);
-- alter table public.products
--   add constraint products_mrp_usd_nonneg check (mrp_usd is null or mrp_usd >= 0);
