-- Policies / static pages shown in footer (editable via Admin)

create table if not exists public.policies (
  id bigserial primary key,
  title text not null,
  slug text not null unique,
  content text default '',
  footer_group text not null default 'Privacy & Legal',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Seed common footer items (you can edit these in Admin later)
insert into public.policies (title, slug, content, footer_group)
values
  ('Privacy and Cookie Policy', 'privacy-cookie-policy', '', 'Privacy & Legal'),
  ('Terms & Conditions', 'terms-conditions', '', 'Privacy & Legal'),
  ('Manually Manage Cookies', 'manage-cookies', '', 'Privacy & Legal'),
  ('Returns Information', 'returns-information', '', 'Help'),
  ('Delivery Information', 'delivery-information', '', 'Help'),
  ('Product Recall', 'product-recall', '', 'Help'),
  ('Media & Press', 'media-press', '', 'Other Services'),
  ('The Company', 'the-company', '', 'Other Services'),
  ('Careers', 'careers', '', 'Other Services')
on conflict (slug) do nothing;
