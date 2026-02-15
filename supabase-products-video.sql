-- Add product video URL column (optional)

alter table if exists public.products
  add column if not exists video_url text;

create index if not exists products_video_url_idx on public.products (video_url);
