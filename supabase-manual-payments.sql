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

  -- Where each received amount was placed
  delivery_partner_to text not null default 'bank' check (delivery_partner_to in ('bank','hand')),
  paypal_to text not null default 'bank' check (paypal_to in ('bank','hand')),
  upi_whatsapp_to text not null default 'bank' check (upi_whatsapp_to in ('bank','hand')),

  -- Cash placement
  cash_in_bank_inr numeric not null default 0,
  cash_in_hand_inr numeric not null default 0,

  created_by uuid null,
  updated_by uuid null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Backfill columns for existing installations
alter table public.manual_payments add column if not exists delivery_partner_to text;
alter table public.manual_payments add column if not exists paypal_to text;
alter table public.manual_payments add column if not exists upi_whatsapp_to text;

update public.manual_payments set delivery_partner_to = coalesce(delivery_partner_to, 'bank') where delivery_partner_to is null;
update public.manual_payments set paypal_to = coalesce(paypal_to, 'bank') where paypal_to is null;
update public.manual_payments set upi_whatsapp_to = coalesce(upi_whatsapp_to, 'bank') where upi_whatsapp_to is null;

alter table public.manual_payments alter column delivery_partner_to set not null;
alter table public.manual_payments alter column paypal_to set not null;
alter table public.manual_payments alter column upi_whatsapp_to set not null;

alter table public.manual_payments alter column delivery_partner_to set default 'bank';
alter table public.manual_payments alter column paypal_to set default 'bank';
alter table public.manual_payments alter column upi_whatsapp_to set default 'bank';

alter table public.manual_payments drop constraint if exists manual_payments_delivery_partner_to_check;
alter table public.manual_payments add constraint manual_payments_delivery_partner_to_check check (delivery_partner_to in ('bank','hand'));

alter table public.manual_payments drop constraint if exists manual_payments_paypal_to_check;
alter table public.manual_payments add constraint manual_payments_paypal_to_check check (paypal_to in ('bank','hand'));

alter table public.manual_payments drop constraint if exists manual_payments_upi_whatsapp_to_check;
alter table public.manual_payments add constraint manual_payments_upi_whatsapp_to_check check (upi_whatsapp_to in ('bank','hand'));

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


-- Cash takeouts (Admin only)
create table if not exists public.cash_takeouts (
  id bigserial primary key,
  region text not null default 'IN' check (region in ('IN','USA')),
  take_date date not null,
  source text not null check (source in ('bank','hand')),
  amount_inr numeric not null default 0,
  purpose text not null,
  created_by uuid null,
  updated_by uuid null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists cash_takeouts_region_date_idx
  on public.cash_takeouts (region, take_date desc);

drop trigger if exists trg_cash_takeouts_updated_at on public.cash_takeouts;
create trigger trg_cash_takeouts_updated_at
before update on public.cash_takeouts
for each row execute function public.set_updated_at();

alter table public.cash_takeouts enable row level security;
