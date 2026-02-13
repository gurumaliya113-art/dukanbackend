-- Fix: allow PayPal orders to be inserted
-- Error seen: new row for relation "orders" violates check constraint "orders_payment_method_check"
-- Run this in Supabase SQL Editor.

-- Optional: see current constraint definition (Postgres UI may vary)
-- SELECT conname, pg_get_constraintdef(c.oid)
-- FROM pg_constraint c
-- JOIN pg_class t ON t.oid = c.conrelid
-- JOIN pg_namespace n ON n.oid = t.relnamespace
-- WHERE t.relname = 'orders' AND conname = 'orders_payment_method_check';

ALTER TABLE public.orders
  DROP CONSTRAINT IF EXISTS orders_payment_method_check;

ALTER TABLE public.orders
  ADD CONSTRAINT orders_payment_method_check
  CHECK (payment_method IN ('COD', 'PAYPAL'));
