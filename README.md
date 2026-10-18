# Shelter Finder

Shelter Finder is a shared shelter directory where shelters can add listings and visitors can browse by animal type, use the map, save listings, and leave reviews.

## Open the app

Published site: [bjmembers1-ops.github.io/shelter-finder](https://bjmembers1-ops.github.io/shelter-finder/)

Admin backroom: [bjmembers1-ops.github.io/shelter-finder/admin.html](https://bjmembers1-ops.github.io/shelter-finder/admin.html)

## Shelter registration

The directory starts with **no example/demo shelters**.

A shelter can submit its own:
- shelter name
- registration contact
- email
- website (optional)
- phone number
- location
- animal types
- shelter photo (optional)
- optional priority scores

Submissions are automatically checked for required contact details and valid field formats. Listings that pass are marked **Auto-approved** and published immediately.

> Auto-approved means the form passed the site's automatic checks. It is not a government, licensing, or legal certification of the shelter.

Duplicate shelter-name + location combinations are rejected.

## Reviews

Visitors can leave a 1-to-5 rating and a written review on each shelter. Reviews are shared across devices, validated by a Supabase Edge Function, and rate-limited. Administrators can remove spam or unsafe reviews from the backroom.

## Backend and security

Supabase stores shelters, reviews, and administrator membership. Row Level Security allows the public to read published listings and reviews while keeping moderation actions restricted to approved accounts. Public submissions pass through rate-limited Edge Functions; no secret key is included in the frontend.

## Set up an administrator

1. In the Supabase dashboard, open **Authentication > Users** and create the administrator account.
2. Copy that user's UUID.
3. In the SQL editor, run `insert into public.admin_users (user_id) values ('USER_UUID_HERE');` with the real UUID.
4. Sign in at `admin.html` with that account's email and password.
