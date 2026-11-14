create table public.documents (id uuid primary key, org text, content text);
alter table public.documents enable row level security;
create policy "admins read all" on public.documents for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create or replace function public.is_admin() returns boolean
language plpgsql security definer as $$
begin
  -- ; semicolons inside dollar quotes must not split the statement
  return exists (select 1 from public.admins where user_id = auth.uid());
end;
$$;

create or replace function public.safe_fn() returns int
language sql security definer set search_path = '' as $fn$ select 1; $fn$;

create view public.order_totals as select user_id, sum(total) from public.orders group by user_id;
create view public.safe_view with (security_invoker = true) as select id from public.profiles;

grant insert, update on table public.orders to anon;

create table public.temp_stuff (id int);
drop table if exists public.temp_stuff;

create table public.legacy (id int);
alter table public.legacy enable row level security;
alter table public.legacy disable row level security;
