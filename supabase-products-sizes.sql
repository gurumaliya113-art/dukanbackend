-- Add product-level available sizes
-- Stores a list like: {"S","M","L"} or {"0-1 year","1-2 year"}

alter table public.products
add column if not exists sizes text[];
