-- Customer login support (email OR phone + password)
--
-- NOTE:
-- - Supabase Auth stores users in auth.users automatically.
-- - This SQL creates an optional public.customers profile table and
--   adds an optional customer_user_id column to public.orders so you can
--   link placed orders to the logged-in customer.
--
-- Run this in Supabase SQL Editor.

-- 1) Customer profile table (optional but recommended)
create table if not exists public.customers (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  full_name text,
  email text,
  phone text
);

alter table public.customers enable row level security;

drop policy if exists customers_select_own on public.customers;
create policy customers_select_own
on public.customers
for select
using (auth.uid() = user_id);

drop policy if exists customers_insert_own on public.customers;
create policy customers_insert_own
on public.customers
for insert
with check (auth.uid() = user_id);

drop policy if exists customers_update_own on public.customers;
create policy customers_update_own
on public.customers
for update
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

-- 2) Link orders to logged-in customer (optional)
alter table public.orders
add column if not exists customer_user_id uuid references auth.users(id);

create index if not exists orders_customer_user_id_idx
on public.orders(customer_user_id);

-- Optional: if you ever want customers to read their own orders from frontend:
-- (DON'T enable these unless you understand your current orders RLS.)
-- alter table public.orders enable row level security;
-- drop policy if exists orders_select_own on public.orders;
-- create policy orders_select_own
-- on public.orders
-- for select
-- using (auth.uid() = customer_user_id);
