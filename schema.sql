-- ============================================================
-- 로드자전거 동호회 사이트 - Supabase 데이터베이스 스키마
-- 모든 테이블은 접두어 rbc_ (Road Bike Club) 사용
-- Supabase 대시보드 > SQL Editor 에서 전체 내용을 실행하세요.
-- ============================================================

create extension if not exists pgcrypto;

-- ------------------------------------------------------------
-- 1. 회원 프로필 (auth.users 확장)
-- ------------------------------------------------------------
create table if not exists public.rbc_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text not null,
  phone text,
  role text not null default 'member' check (role in ('member','admin')),
  created_at timestamptz not null default now()
);

-- 회원가입 시 auth.users -> rbc_profiles 자동 생성 트리거
create or replace function public.rbc_handle_new_user()
returns trigger as $$
begin
  insert into public.rbc_profiles (id, email, name, phone)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    new.raw_user_meta_data->>'phone'
  );
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists rbc_on_auth_user_created on auth.users;
create trigger rbc_on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.rbc_handle_new_user();

-- 관리자 여부 판별 함수 (RLS 재귀 방지를 위해 security definer 사용)
create or replace function public.rbc_is_admin()
returns boolean as $$
  select exists (
    select 1 from public.rbc_profiles
    where id = auth.uid() and role = 'admin'
  );
$$ language sql security definer stable;

-- ------------------------------------------------------------
-- 2. 공지사항
-- ------------------------------------------------------------
create table if not exists public.rbc_notices (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  is_pinned boolean not null default false,
  author_id uuid references public.rbc_profiles(id) on delete set null,
  author_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 3. 자유게시판 + 댓글
-- ------------------------------------------------------------
create table if not exists public.rbc_posts (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  author_id uuid references public.rbc_profiles(id) on delete set null,
  author_name text,
  view_count int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.rbc_comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.rbc_posts(id) on delete cascade,
  author_id uuid references public.rbc_profiles(id) on delete set null,
  author_name text,
  content text not null,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 4. 갤러리 (라이딩 사진 후기) - 이미지는 URL로 등록
-- ------------------------------------------------------------
create table if not exists public.rbc_gallery (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text,
  image_url text,
  author_id uuid references public.rbc_profiles(id) on delete set null,
  author_name text,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 5. 정기모임 (연 4회, 관리자 등록)
-- ------------------------------------------------------------
create table if not exists public.rbc_regular_meetups (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  event_date date not null,
  location text,
  capacity int not null default 40,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 6. 소모임 (매달, 지역별 자전거 여행, 관리자 등록)
-- ------------------------------------------------------------
create table if not exists public.rbc_small_meetups (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  region text,
  event_date date not null,
  location text,
  capacity int not null default 15,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 7. 모임 신청
-- ------------------------------------------------------------
create table if not exists public.rbc_applications (
  id uuid primary key default gen_random_uuid(),
  meetup_type text not null check (meetup_type in ('regular','small')),
  meetup_id uuid not null,
  user_id uuid not null references public.rbc_profiles(id) on delete cascade,
  name text not null,
  phone text,
  status text not null default 'pending' check (status in ('pending','approved','canceled')),
  created_at timestamptz not null default now(),
  unique (meetup_type, meetup_id, user_id)
);

-- ============================================================
-- RLS (Row Level Security) 활성화 및 정책
-- ============================================================
alter table public.rbc_profiles         enable row level security;
alter table public.rbc_notices          enable row level security;
alter table public.rbc_posts            enable row level security;
alter table public.rbc_comments         enable row level security;
alter table public.rbc_gallery          enable row level security;
alter table public.rbc_regular_meetups  enable row level security;
alter table public.rbc_small_meetups    enable row level security;
alter table public.rbc_applications     enable row level security;

-- profiles: 본인 또는 관리자만 조회/수정
create policy "rbc_profiles_select" on public.rbc_profiles
  for select using (auth.uid() = id or public.rbc_is_admin());
create policy "rbc_profiles_update" on public.rbc_profiles
  for update using (auth.uid() = id or public.rbc_is_admin());

-- notices: 전체공개 조회, 관리자만 작성/수정/삭제
create policy "rbc_notices_select" on public.rbc_notices for select using (true);
create policy "rbc_notices_insert" on public.rbc_notices for insert with check (public.rbc_is_admin());
create policy "rbc_notices_update" on public.rbc_notices for update using (public.rbc_is_admin());
create policy "rbc_notices_delete" on public.rbc_notices for delete using (public.rbc_is_admin());

-- posts: 전체공개 조회, 로그인 회원 작성, 본인/관리자 수정삭제
create policy "rbc_posts_select" on public.rbc_posts for select using (true);
create policy "rbc_posts_insert" on public.rbc_posts for insert with check (auth.uid() = author_id);
create policy "rbc_posts_update" on public.rbc_posts for update using (auth.uid() = author_id or public.rbc_is_admin());
create policy "rbc_posts_delete" on public.rbc_posts for delete using (auth.uid() = author_id or public.rbc_is_admin());

-- comments
create policy "rbc_comments_select" on public.rbc_comments for select using (true);
create policy "rbc_comments_insert" on public.rbc_comments for insert with check (auth.uid() = author_id);
create policy "rbc_comments_delete" on public.rbc_comments for delete using (auth.uid() = author_id or public.rbc_is_admin());

-- gallery
create policy "rbc_gallery_select" on public.rbc_gallery for select using (true);
create policy "rbc_gallery_insert" on public.rbc_gallery for insert with check (auth.uid() = author_id);
create policy "rbc_gallery_update" on public.rbc_gallery for update using (auth.uid() = author_id or public.rbc_is_admin());
create policy "rbc_gallery_delete" on public.rbc_gallery for delete using (auth.uid() = author_id or public.rbc_is_admin());

-- regular meetups: 전체공개 조회, 관리자만 작성/수정/삭제
create policy "rbc_regular_select" on public.rbc_regular_meetups for select using (true);
create policy "rbc_regular_insert" on public.rbc_regular_meetups for insert with check (public.rbc_is_admin());
create policy "rbc_regular_update" on public.rbc_regular_meetups for update using (public.rbc_is_admin());
create policy "rbc_regular_delete" on public.rbc_regular_meetups for delete using (public.rbc_is_admin());

-- small meetups
create policy "rbc_small_select" on public.rbc_small_meetups for select using (true);
create policy "rbc_small_insert" on public.rbc_small_meetups for insert with check (public.rbc_is_admin());
create policy "rbc_small_update" on public.rbc_small_meetups for update using (public.rbc_is_admin());
create policy "rbc_small_delete" on public.rbc_small_meetups for delete using (public.rbc_is_admin());

-- applications: 본인 또는 관리자만 조회/수정/삭제, 본인만 신청(작성)
create policy "rbc_apps_select" on public.rbc_applications for select using (auth.uid() = user_id or public.rbc_is_admin());
create policy "rbc_apps_insert" on public.rbc_applications for insert with check (auth.uid() = user_id);
create policy "rbc_apps_update" on public.rbc_applications for update using (auth.uid() = user_id or public.rbc_is_admin());
create policy "rbc_apps_delete" on public.rbc_applications for delete using (auth.uid() = user_id or public.rbc_is_admin());

-- ============================================================
-- 샘플 데이터 (정기모임 4회 + 소모임 예시) - 없어도 무방, 데모용
-- ============================================================
insert into public.rbc_regular_meetups (title, description, event_date, location, capacity) values
('2026년 봄 정기모임', '벚꽃길 라이딩과 신입 회원 환영식', '2026-04-11', '한강 여의도 나들목', 40),
('2026년 여름 정기모임', '야간 라이딩과 정기 총회', '2026-07-18', '서울숲 입구', 40),
('2026년 가을 정기모임', '단풍길 라이딩 대회', '2026-10-17', '남한산성 입구', 40),
('2026년 겨울 정기모임', '송년회 및 우수 회원 시상식', '2026-12-12', '한강 반포 나들목', 40)
on conflict do nothing;

insert into public.rbc_small_meetups (title, description, region, event_date, location, capacity) values
('제주 해안도로 소모임', '제주 동쪽 해안도로를 따라 달리는 당일 라이딩', '제주', '2026-09-27', '제주 함덕해수욕장', 15),
('남해 다랭이마을 소모임', '남해 바닷길과 다랭이마을 라이딩', '경남', '2026-10-11', '남해대교 주차장', 15)
on conflict do nothing;

-- ============================================================
-- 최초 관리자 지정 방법 (회원가입 후 아래 UPDATE 실행)
-- ============================================================
-- update public.rbc_profiles set role = 'admin' where email = '관리자이메일@example.com';
