-- Manual daily payments (Admin only)
-- Stores daily totals entered manually for each region.

create table if not exists public.manual_payments (
  id bigserial primary key,
  region text not null check (region in ('IN','USA')),
  pay_date date not null,

  -- Received today (store in INR per current UI)
  delivery_partner_inr numeric not null default 0,
  paypal_inr numeric not null default 0,
  upi_whatsapp_inr numeric not null default 0,

  -- Cash placement
  cash_in_bank_inr numeric not null default 0,
  cash_in_hand_inr numeric not null default 0,

  created_by uuid null,
  updated_by uuid null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists manual_payments_region_date_uidx
  on public.manual_payments (region, pay_date);

-- updated_at trigger
create or replace function public.set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_manual_payments_updated_at on public.manual_payments;
create trigger trg_manual_payments_updated_at
before update on public.manual_payments
for each row execute function public.set_updated_at();

-- RLS: keep enabled, allow only service role (backend) or explicit admin policies.
alter table public.manual_payments enable row level security;

-- Minimal policies: deny by default.
-- If you want to allow direct Supabase client access for admins, add policies separately.
