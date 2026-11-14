-- Example project with deliberate mistakes, used by the test suite.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text,
  bio text
);
alter table public.profiles enable row level security;
create policy "Profiles are public" on public.profiles for select using (true);
create policy "Users update own profile" on public.profiles for update
  to authenticated using (auth.uid() = id);

create table if not exists notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid(),
  body text -- a comment; with a semicolon
);

create table public.orders (id bigint primary key, user_id uuid, total numeric);
alter table public.orders enable row level security;
create policy "anyone can insert orders" on public.orders for insert to anon, authenticated with check (true);
create policy "own orders" on public.orders for select to authenticated using ((select auth.uid()) = user_id);

create table public.admin_only (id int primary key);
alter table public.admin_only enable row level security;

create table private.internal (id int);
