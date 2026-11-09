-- ===== TABEL =====
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  phone text,
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);

create table public.partners (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  address text not null,
  latitude double precision,
  longitude double precision,
  phone text,
  open_hours text,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table public.partner_waste_types (
  partner_id uuid not null references public.partners(id) on delete cascade,
  waste_type text not null check (waste_type in ('organik','plastik','kertas','kaca','logam')),
  primary key (partner_id, waste_type)
);

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  label text not null,
  confidence numeric(5,2),
  image_url text,
  created_at timestamptz not null default now()
);

create table public.requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  partner_id uuid not null references public.partners(id),
  type text not null check (type in ('dropoff','pickup')),
  waste_type text not null check (waste_type in ('organik','plastik','kertas','kaca','logam')),
  estimated_weight_kg numeric(6,2),
  scheduled_at timestamptz,
  pickup_address text,
  note text,
  status text not null default 'menunggu'
    check (status in ('menunggu','dikonfirmasi','dijemput','selesai','ditolak')),
  created_at timestamptz not null default now(),
  constraint pickup_needs_address check (type <> 'pickup' or pickup_address is not null)
);

-- ===== FUNGSI BANTU =====
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

-- profil otomatis dibuat saat user mendaftar
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''));
  return new;
end;
$$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ===== HAK AKSES TABEL =====
revoke all on public.profiles, public.partners, public.partner_waste_types,
  public.scans, public.requests from anon, authenticated;

grant select on public.profiles to authenticated;
grant update (full_name, phone) on public.profiles to authenticated;
grant select, insert, update, delete on public.partners, public.partner_waste_types to authenticated;
grant select, insert on public.scans to authenticated;
grant select, insert, update on public.requests to authenticated;

-- ===== RLS =====
alter table public.profiles enable row level security;
alter table public.partners enable row level security;
alter table public.partner_waste_types enable row level security;
alter table public.scans enable row level security;
alter table public.requests enable row level security;

create policy "profiles_select" on public.profiles for select to authenticated
  using (id = (select auth.uid()) or public.is_admin());
create policy "profiles_update_own" on public.profiles for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

create policy "partners_select" on public.partners for select to authenticated
  using (is_active or public.is_admin());
create policy "partners_admin_write" on public.partners for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy "pwt_select" on public.partner_waste_types for select to authenticated
  using (true);
create policy "pwt_admin_write" on public.partner_waste_types for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy "scans_select" on public.scans for select to authenticated
  using (user_id = (select auth.uid()) or public.is_admin());
create policy "scans_insert_own" on public.scans for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "requests_select" on public.requests for select to authenticated
  using (user_id = (select auth.uid()) or public.is_admin());
create policy "requests_insert_own" on public.requests for insert to authenticated
  with check (user_id = (select auth.uid()) and status = 'menunggu');
create policy "requests_admin_update" on public.requests for update to authenticated
  using (public.is_admin()) with check (public.is_admin());