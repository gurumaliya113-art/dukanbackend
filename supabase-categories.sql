-- Add product category (New Arrivals / Men / Women / Kids)
-- Canonical values stored as: 'new' | 'men' | 'women' | 'kids'

alter table public.products
add column if not exists category text;

update public.products
set category = 'new'
where category is null;

-- Optional: basic constraint (comment out if you want fully custom categories)
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'products_category_check'
  ) then
    alter table public.products
      add constraint products_category_check
      check (category in ('new','men','women','kids'));
  end if;
end $$;
