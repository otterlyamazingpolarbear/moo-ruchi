-- Moo-ruchi gallery: run this once in Supabase (SQL Editor > New query > paste > Run).

-- Photos are stored in a public bucket (anyone can view, only signed-in people can add).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('gallery', 'gallery', true, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

-- Posts
create table if not exists public.gallery_posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  author_name text not null check (char_length(author_name) between 1 and 60),
  caption text not null default '' check (char_length(caption) <= 160),
  image_path text not null,
  created_at timestamptz not null default now()
);
create index if not exists gallery_posts_created_idx on public.gallery_posts (created_at desc);

-- Admins (the site owner). Add yourself after you create your account; see the bottom of this file.
create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

alter table public.gallery_posts enable row level security;
alter table public.admins enable row level security;

drop policy if exists "anyone can view posts" on public.gallery_posts;
create policy "anyone can view posts" on public.gallery_posts for select using (true);

drop policy if exists "signed-in users can post as themselves" on public.gallery_posts;
create policy "signed-in users can post as themselves" on public.gallery_posts
  for insert to authenticated with check (user_id = auth.uid());

drop policy if exists "owners and admin can delete posts" on public.gallery_posts;
drop policy if exists "owners within 5 min and admin can delete posts" on public.gallery_posts;
create policy "owners within 5 min and admin can delete posts" on public.gallery_posts
  for delete to authenticated
  using ((user_id = auth.uid() and created_at > now() - interval '5 minutes') or public.is_admin());

drop policy if exists "see own admin row" on public.admins;
create policy "see own admin row" on public.admins for select to authenticated using (user_id = auth.uid());

-- Storage rules: anyone can view; signed-in users can upload into their own folder; delete own (or admin deletes any).
drop policy if exists "gallery public read" on storage.objects;
create policy "gallery public read" on storage.objects for select using (bucket_id = 'gallery');

drop policy if exists "gallery upload to own folder" on storage.objects;
create policy "gallery upload to own folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'gallery' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "gallery delete own or admin" on storage.objects;
drop policy if exists "gallery delete own within 5 min or admin" on storage.objects;
create policy "gallery delete own within 5 min or admin" on storage.objects for delete to authenticated
  using (bucket_id = 'gallery' and (
    ((storage.foldername(name))[1] = auth.uid()::text and created_at > now() - interval '5 minutes')
    or public.is_admin()));

-- AFTER you have created your own account on the site, run this line once with your email
-- (do not save your email in the repository):
--   insert into public.admins (user_id) select id from auth.users where email = 'YOUR-EMAIL-HERE';

-- Admin tools (the site shows a "Members" panel to admins): list members and change roles.
create or replace function public.list_members()
returns table (id uuid, name text, email text, created_at timestamptz, is_admin boolean)
language plpgsql stable security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'admins only'; end if;
  return query
    select u.id, coalesce(u.raw_user_meta_data->>'name', ''), u.email::text, u.created_at,
           exists (select 1 from public.admins a where a.user_id = u.id)
    from auth.users u order by u.created_at;
end $$;

create or replace function public.set_admin(target uuid, make_admin boolean)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admins only'; end if;
  if make_admin then
    insert into public.admins (user_id) values (target) on conflict do nothing;
  else
    if target = auth.uid() then raise exception 'You cannot remove your own admin role'; end if;
    delete from public.admins where user_id = target;
  end if;
end $$;

revoke execute on function public.list_members() from public, anon;
revoke execute on function public.set_admin(uuid, boolean) from public, anon;
grant execute on function public.list_members() to authenticated;
grant execute on function public.set_admin(uuid, boolean) to authenticated;

-- Multi-photo posts (up to 5 photos per post, shown as a carousel).
alter table public.gallery_posts add column if not exists image_paths text[] not null default '{}';
alter table public.gallery_posts drop constraint if exists gallery_posts_max_photos;
alter table public.gallery_posts add constraint gallery_posts_max_photos check (cardinality(image_paths) <= 5);
update public.gallery_posts set image_paths = array[image_path] where cardinality(image_paths) = 0;

-- Editing posts: owners (and admins) can change the caption and reorder photos, nothing else.
revoke update on public.gallery_posts from anon, authenticated;
grant update (caption, image_paths, image_path) on public.gallery_posts to authenticated;
drop policy if exists "owners and admin can edit posts" on public.gallery_posts;
create policy "owners and admin can edit posts" on public.gallery_posts
  for update to authenticated
  using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());
create or replace function public.gallery_posts_guard() returns trigger
language plpgsql set search_path = public as $$
begin
  if new.image_paths is distinct from old.image_paths and not (
    cardinality(new.image_paths) = cardinality(old.image_paths)
    and new.image_paths @> old.image_paths and new.image_paths <@ old.image_paths
  ) then
    raise exception 'Photos can only be reordered';
  end if;
  new.image_path := new.image_paths[1];
  return new;
end $$;
drop trigger if exists gallery_posts_guard on public.gallery_posts;
create trigger gallery_posts_guard before update on public.gallery_posts
  for each row execute function public.gallery_posts_guard();

-- Favorites saved to each person's account.
create table if not exists public.favorites (
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  recipe_id text not null check (char_length(recipe_id) between 1 and 80),
  created_at timestamptz not null default now(),
  primary key (user_id, recipe_id)
);
alter table public.favorites enable row level security;
revoke all on public.favorites from anon;
grant select, insert, delete on public.favorites to authenticated;
drop policy if exists "see own favorites" on public.favorites;
create policy "see own favorites" on public.favorites for select to authenticated using (user_id = auth.uid());
drop policy if exists "add own favorites" on public.favorites;
create policy "add own favorites" on public.favorites for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "remove own favorites" on public.favorites;
create policy "remove own favorites" on public.favorites for delete to authenticated using (user_id = auth.uid());

-- Recipes live in the database so only signed-in members can read them (admins can add and edit).
-- Each row: id, sort order, and `data` (title, cat, photo, ingredients[], steps[], notes[], tags[], ...).
create table if not exists public.recipes (
  id text primary key check (char_length(id) between 1 and 80),
  sort int not null default 0,
  data jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.recipes enable row level security;
revoke all on public.recipes from anon;
grant select, insert, update, delete on public.recipes to authenticated;
drop policy if exists "signed-in users can read recipes" on public.recipes;
create policy "signed-in users can read recipes" on public.recipes for select to authenticated using (true);
drop policy if exists "admins add recipes" on public.recipes;
create policy "admins add recipes" on public.recipes for insert to authenticated with check (public.is_admin());
drop policy if exists "admins edit recipes" on public.recipes;
create policy "admins edit recipes" on public.recipes for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "admins delete recipes" on public.recipes;
create policy "admins delete recipes" on public.recipes for delete to authenticated using (public.is_admin());

-- Private bucket for recipe photos (files named like the `photo` field in each recipe).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('recipe-photos', 'recipe-photos', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;
drop policy if exists "signed-in users can view recipe photos" on storage.objects;
create policy "signed-in users can view recipe photos" on storage.objects for select to authenticated using (bucket_id = 'recipe-photos');
drop policy if exists "admins manage recipe photos" on storage.objects;
create policy "admins manage recipe photos" on storage.objects for all to authenticated
  using (bucket_id = 'recipe-photos' and public.is_admin()) with check (bucket_id = 'recipe-photos' and public.is_admin());

-- Recipe requests and recipes people send in (shown to admins on the Requests tab to check off).
create table if not exists public.recipe_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  kind text not null check (kind in ('request','add')),
  recipe_name text not null check (char_length(recipe_name) between 1 and 200),
  details text not null default '' check (char_length(details) <= 20000),
  tags text[] not null default '{}',
  extra text not null default '' check (char_length(extra) <= 5000),
  from_name text not null default '' check (char_length(from_name) <= 100),
  author_name text not null default '' check (char_length(author_name) <= 100),
  done boolean not null default false,
  done_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists recipe_requests_created_idx on public.recipe_requests (created_at desc);
alter table public.recipe_requests enable row level security;
revoke all on public.recipe_requests from anon, authenticated;
grant select, insert, delete on public.recipe_requests to authenticated;
grant update (done, done_at) on public.recipe_requests to authenticated;
drop policy if exists "send own requests" on public.recipe_requests;
create policy "send own requests" on public.recipe_requests for insert to authenticated with check (user_id = auth.uid() and done = false);
drop policy if exists "read own or admin" on public.recipe_requests;
create policy "read own or admin" on public.recipe_requests for select to authenticated using (user_id = auth.uid() or public.is_admin());
drop policy if exists "admins update requests" on public.recipe_requests;
create policy "admins update requests" on public.recipe_requests for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "admins delete requests" on public.recipe_requests;
create policy "admins delete requests" on public.recipe_requests for delete to authenticated using (public.is_admin());
