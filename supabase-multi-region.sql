-- Run this in Supabase SQL editor (one-time)

-- 1) Products: store per-region pricing
alter table if exists public.products
  add column if not exists price_inr numeric;

alter table if exists public.products
  add column if not exists price_usd numeric;

-- Backfill INR from legacy price column
update public.products
set price_inr = price
where price_inr is null;

-- 2) Orders: store which currency was used
alter table if exists public.orders
  add column if not exists currency text;
