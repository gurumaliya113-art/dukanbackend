-- Add cost price columns for products (used for profit calculations)

alter table if exists public.products
  add column if not exists cost_inr numeric,
  add column if not exists cost_usd numeric;

-- Optional: ensure non-negative values
do $$
begin
  begin
    alter table public.products
      add constraint products_cost_inr_nonneg check (cost_inr is null or cost_inr >= 0);
  exception
    when duplicate_object then null;
  end;

  begin
    alter table public.products
      add constraint products_cost_usd_nonneg check (cost_usd is null or cost_usd >= 0);
  exception
    when duplicate_object then null;
  end;
end $$;

create index if not exists products_cost_inr_idx on public.products (cost_inr);
create index if not exists products_cost_usd_idx on public.products (cost_usd);
