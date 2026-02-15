-- Add manual cost tracking columns for orders
-- These are set by admin from the Admin Panel (manual entry).

alter table if exists public.orders
  add column if not exists delivery_cost numeric,
  add column if not exists packing_cost numeric,
  add column if not exists ads_cost numeric,
  add column if not exists rto_cost numeric;

do $$
begin
  begin
    alter table public.orders
      add constraint orders_delivery_cost_nonneg check (delivery_cost is null or delivery_cost >= 0);
  exception
    when duplicate_object then null;
  end;

  begin
    alter table public.orders
      add constraint orders_packing_cost_nonneg check (packing_cost is null or packing_cost >= 0);
  exception
    when duplicate_object then null;
  end;

  begin
    alter table public.orders
      add constraint orders_ads_cost_nonneg check (ads_cost is null or ads_cost >= 0);
  exception
    when duplicate_object then null;
  end;

  begin
    alter table public.orders
      add constraint orders_rto_cost_nonneg check (rto_cost is null or rto_cost >= 0);
  exception
    when duplicate_object then null;
  end;
end $$;

create index if not exists orders_delivery_cost_idx on public.orders (delivery_cost);
create index if not exists orders_packing_cost_idx on public.orders (packing_cost);
create index if not exists orders_ads_cost_idx on public.orders (ads_cost);
create index if not exists orders_rto_cost_idx on public.orders (rto_cost);
