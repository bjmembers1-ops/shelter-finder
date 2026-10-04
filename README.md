# Shelter Finder

Shelter Finder is a single-page app where animal shelters can add their own listing and visitors can browse shelters by animal type, contact them, save listings, and use the interactive map.

## Open the app

Open `outputs/index.html` in a browser.

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

## Current storage limitation

This is still a frontend-only prototype. User-added shelters are saved in that browser's local storage, not in a shared backend database. A production version needs a database/API so a shelter submitted on one device appears for every visitor.
