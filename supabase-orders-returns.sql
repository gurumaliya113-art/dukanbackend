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

-- Notes:
-- - Returns are requested via backend endpoint /customer/orders/:id/return
-- - Return window is enforced in backend as 7 days from created_at
