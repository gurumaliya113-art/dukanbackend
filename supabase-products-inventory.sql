-- Inventory fields for products (SKU / Barcode / Quantity)
-- Run this in Supabase SQL Editor.

alter table public.products
  add column if not exists sku text,
  add column if not exists barcode text,
  add column if not exists quantity integer;

-- Optional sanity check (safe if you want to prevent negative stock)
alter table public.products
  drop constraint if exists products_quantity_nonneg;
alter table public.products
  add constraint products_quantity_nonneg check (quantity is null or quantity >= 0);

-- Optional indexes for faster lookup (SKU / barcode searches)
create index if not exists products_sku_idx on public.products (sku);
create index if not exists products_barcode_idx on public.products (barcode);
