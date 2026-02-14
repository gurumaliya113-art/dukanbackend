 -- Order history + Returns support
-- Run in Supabase SQL Editor

-- 1) Link orders to customer login (if not already added)
alter table public.orders
add column if not exists customer_user_id uuid references auth.users(id);

create index if not exists orders_customer_user_id_idx
on public.orders(customer_user_id);

-- 2) Return request columns
alter table public.orders
add column if not exists return_status text,
add column if not exists return_requested_at timestamptz,
add column if not exists return_reason text;

create index if not exists orders_return_status_idx
on public.orders(return_status);

-- 3) Order tracking / delivery ETA support
-- Admin can update these fields manually from Admin Panel.
alter table public.orders
add column if not exists estimated_delivery_at timestamptz,
add column if not exists picked_up_from text,
add column if not exists picked_up_at timestamptz,
add column if not exists out_for_delivery boolean not null default false,
add column if not exists out_for_delivery_at timestamptz,
add column if not exists delivered_at timestamptz;

create index if not exists orders_estimated_delivery_at_idx
on public.orders(estimated_delivery_at);

create index if not exists orders_out_for_delivery_idx
on public.orders(out_for_delivery);

-- 4) Multiple "received at" updates (e.g., Delhi -> Gurgaon -> ...)
-- Stored as a separate table so you can add unlimited tracking checkpoints.
create extension if not exists pgcrypto;

create table if not exists public.order_tracking_updates (
	id uuid primary key default gen_random_uuid(),
	-- IMPORTANT: order_id type must match public.orders.id type.
	-- In this project, orders.id is bigint.
	order_id bigint not null references public.orders(id) on delete cascade,
	location text not null,
	note text,
	created_at timestamptz not null default now()
);

create index if not exists order_tracking_updates_order_id_idx
on public.order_tracking_updates(order_id);

create index if not exists order_tracking_updates_created_at_idx
on public.order_tracking_updates(created_at desc);

-- Lock down direct table access (recommended). Backend uses service role, so it still works.
alter table public.order_tracking_updates enable row level security;

drop policy if exists order_tracking_updates_select_own on public.order_tracking_updates;
create policy order_tracking_updates_select_own
on public.order_tracking_updates
for select
using (
	exists (
		select 1
		from public.orders o
		where o.id = order_id
			and o.customer_user_id = auth.uid()
	)
);

-- Notes:
-- - Returns are requested via backend endpoint /customer/orders/:id/return
-- - Return window is enforced in backend as 7 days from created_at
-- - Tracking updates are written by backend admin endpoints and shown in My Account
