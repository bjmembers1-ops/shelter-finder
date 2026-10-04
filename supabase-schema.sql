-- Shelter Finder shared database schema
-- Run in Supabase SQL editor.

create extension if not exists pgcrypto;

create table if not exists public.shelters (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  contact_name text not null,
  email text not null,
  website text,
  phone text not null,
  location text not null,
  photo text,
  scored boolean not null default false,
  main_type text not null check (main_type in ('dogs','cats','rabbits','birds','other')),
  animal_types text[] not null default array['other']::text[],
  animals smallint check (animals between 0 and 25),
  workers smallint check (workers between 0 and 25),
  food smallint check (food between 0 and 25),
  space smallint check (space between 0 and 25),
  latitude double precision check (latitude between -90 and 90),
  longitude double precision check (longitude between -180 and 180),
  verification_status text not null default 'pending',
  verification_method text,
  verified_at timestamptz,
  published boolean not null default false,
  created_at timestamptz not null default now()
);

create unique index if not exists shelters_unique_name_location
on public.shelters (lower(name), lower(location));

create or replace function public.auto_verify_shelter()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  digits text;
begin
  new.name := btrim(new.name);
  new.contact_name := btrim(new.contact_name);
  new.email := lower(btrim(new.email));
  new.phone := btrim(new.phone);
  new.location := btrim(new.location);
  new.website := nullif(btrim(coalesce(new.website, '')), '');

  if length(new.name) < 2 then
    raise exception 'Shelter name is too short';
  end if;

  if length(new.contact_name) < 2 then
    raise exception 'Contact name is too short';
  end if;

  if new.email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    raise exception 'Invalid email address';
  end if;

  digits := regexp_replace(new.phone, '[^0-9]', '', 'g');
  if length(digits) < 7 then
    raise exception 'Invalid phone number';
  end if;

  if length(new.location) < 4 then
    raise exception 'Location is too short';
  end if;

  if new.website is not null and new.website !~* '^https?://' then
    raise exception 'Website must use http or https';
  end if;

  if cardinality(new.animal_types) < 1 or cardinality(new.animal_types) > 5 then
    raise exception 'Choose between 1 and 5 animal types';
  end if;

  new.verification_status := 'auto-approved';
  new.verification_method := 'server-required-fields-and-contact-format';
  new.verified_at := now();
  new.published := true;
  return new;
end;
$$;

drop trigger if exists shelters_auto_verify_before_insert on public.shelters;
create trigger shelters_auto_verify_before_insert
before insert on public.shelters
for each row execute function public.auto_verify_shelter();

alter table public.shelters enable row level security;

drop policy if exists "Public can read published shelters" on public.shelters;
create policy "Public can read published shelters"
on public.shelters
for select
to anon
using (published = true);

drop policy if exists "Public can submit shelters" on public.shelters;
create policy "Public can submit shelters"
on public.shelters
for insert
to anon
with check (
  published = true
  and verification_status = 'auto-approved'
  and length(name) >= 2
  and length(contact_name) >= 2
  and length(location) >= 4
);

grant usage on schema public to anon;
grant select on public.shelters to anon;
grant insert (
  name, contact_name, email, website, phone, location, photo,
  scored, main_type, animal_types, animals, workers, food, space,
  latitude, longitude
) on public.shelters to anon;

-- No anonymous update/delete grants are issued.


-- The trigger function should not be directly callable through the public API.
revoke execute on function public.auto_verify_shelter() from public;
revoke execute on function public.auto_verify_shelter() from anon;
revoke execute on function public.auto_verify_shelter() from authenticated;


-- Security hardening: public clients cannot write shelter rows directly.
drop policy if exists "Public can submit shelters" on public.shelters;
revoke insert on public.shelters from anon;
revoke insert on public.shelters from authenticated;

-- Private rate-limit metadata. Only backend service credentials may access this table.
create table if not exists public.submission_attempts (
  id bigint generated always as identity primary key,
  ip_hash text not null check (length(ip_hash) = 64),
  created_at timestamptz not null default now()
);

create index if not exists submission_attempts_ip_time_idx
  on public.submission_attempts (ip_hash, created_at desc);

alter table public.submission_attempts enable row level security;
revoke all on public.submission_attempts from public;
revoke all on public.submission_attempts from anon;
revoke all on public.submission_attempts from authenticated;

drop policy if exists "No public reads submission attempts" on public.submission_attempts;
create policy "No public reads submission attempts"
on public.submission_attempts
for select
to public
using (false);

drop policy if exists "No public inserts submission attempts" on public.submission_attempts;
create policy "No public inserts submission attempts"
on public.submission_attempts
for insert
to public
with check (false);

drop policy if exists "No public updates submission attempts" on public.submission_attempts;
create policy "No public updates submission attempts"
on public.submission_attempts
for update
to public
using (false)
with check (false);

drop policy if exists "No public deletes submission attempts" on public.submission_attempts;
create policy "No public deletes submission attempts"
on public.submission_attempts
for delete
to public
using (false);

-- Database-level input limits.
alter table public.shelters
  add constraint shelters_name_length_chk check (char_length(name) between 2 and 120),
  add constraint shelters_contact_name_length_chk check (char_length(contact_name) between 2 and 120),
  add constraint shelters_email_length_chk check (char_length(email) between 3 and 254),
  add constraint shelters_phone_length_chk check (char_length(phone) between 7 and 40),
  add constraint shelters_location_length_chk check (char_length(location) between 4 and 300),
  add constraint shelters_website_length_chk check (website is null or char_length(website) <= 500),
  add constraint shelters_website_scheme_chk check (website is null or website ~* '^https?://'),
  add constraint shelters_photo_safe_chk check (
    photo is null or (
      char_length(photo) <= 1100000
      and photo ~ '^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$'
    )
  ),
  add constraint shelters_animal_types_chk check (
    cardinality(animal_types) between 1 and 5
    and animal_types <@ array['dogs','cats','rabbits','birds','other']::text[]
  );

-- The trigger does not require elevated privileges.
create or replace function public.auto_verify_shelter()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare
  digits text;
begin
  new.name := btrim(new.name);
  new.contact_name := btrim(new.contact_name);
  new.email := lower(btrim(new.email));
  new.phone := btrim(new.phone);
  new.location := btrim(new.location);
  new.website := nullif(btrim(coalesce(new.website, '')), '');

  if length(new.name) < 2 then
    raise exception 'Shelter name is too short';
  end if;
  if length(new.contact_name) < 2 then
    raise exception 'Contact name is too short';
  end if;
  if new.email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    raise exception 'Invalid email address';
  end if;

  digits := regexp_replace(new.phone, '[^0-9]', '', 'g');
  if length(digits) < 7 or length(digits) > 20 then
    raise exception 'Invalid phone number';
  end if;

  if length(new.location) < 4 then
    raise exception 'Location is too short';
  end if;

  if new.website is not null and new.website !~* '^https?://' then
    raise exception 'Website must use http or https';
  end if;

  if cardinality(new.animal_types) < 1 or cardinality(new.animal_types) > 5 then
    raise exception 'Choose between 1 and 5 animal types';
  end if;

  new.verification_status := 'auto-approved';
  new.verification_method := 'server-validated-submission';
  new.verified_at := now();
  new.published := true;
  return new;
end;
$$;

revoke execute on function public.auto_verify_shelter() from public;
revoke execute on function public.auto_verify_shelter() from anon;
revoke execute on function public.auto_verify_shelter() from authenticated;
