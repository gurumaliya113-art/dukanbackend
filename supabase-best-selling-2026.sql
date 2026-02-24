-- Best Selling Of 2026 (homepage horizontal scroller)
-- Run this in Supabase SQL Editor.

create table if not exists public.best_selling_2026 (
  id bigserial primary key,
  product_id integer not null,
  position integer not null default 0,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint best_selling_2026_product_id_unique unique (product_id),
  constraint best_selling_2026_product_fk foreign key (product_id)
    references public.products (id)
    on delete cascade
);

create index if not exists best_selling_2026_active_position_idx
  on public.best_selling_2026 (active, position);

-- Optional: auto-update updated_at
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_best_selling_2026_updated_at on public.best_selling_2026;
create trigger trg_best_selling_2026_updated_at
before update on public.best_selling_2026
for each row execute function public.set_updated_at();

-- Example inserts (replace 101,102 with real product IDs from public.products)
-- insert into public.best_selling_2026 (product_id, position) values
--   (101, 1),
--   (102, 2);
