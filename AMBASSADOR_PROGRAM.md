# Ambassador Program: `is_ambassador` vs `ambassador_cohort`

No README existed for this before now - this one covers the two ambassador-related
fields on `CustomUser`, since they're easy to conflate but drive different things.

## The two concepts

| Field | Meaning | Drives |
|---|---|---|
| `is_ambassador` (bool) | Current program membership - "is this person an active ambassador right now" | Referral reward threshold (`CustomUser.confirm_referral_rewards` - ambassadors' referred users qualify at ₦10k saved instead of ₦20k), gating the `/api/ambassador/login/` endpoint and ambassador-only dashboard views, and (indirectly) who's eligible to submit an `AmbassadorMonthlyReport` each month |
| `ambassador_cohort` (FK -> `AmbassadorCohort`, nullable) | Which intake they joined (Cohort 1, 2, 3, ...) | Segmentation/messaging only - the mobile admin Email/Push compose screen's Ambassadors -> Cohort picker, CSV exports/recipient filtering (`ambassador_cohort` query param on `_build_admin_user_queryset`), and the `AMBASSADOR_COHORT` Brevo attribute |

**They're independent.** A user can have an `ambassador_cohort` (e.g. Cohort 1)
without `is_ambassador=True` today - most former ambassadors are in exactly this
state. Conversely `is_ambassador=True` with `ambassador_cohort=None` is possible
for anyone marked an ambassador before a cohort was ever assigned. Neither field
implies the other.

**Payments/rewards were not touched when cohort tracking was added.** The stipend
system (`AmbassadorMonthlyReport`, approved/paid via `admin.py`'s
`AmbassadorMonthlyReportAdmin` actions) and the referral-threshold logic both key
off `is_ambassador` exactly as they did before - cohort is additive metadata
layered on top, read by new code only (Brevo sync, the segment filter, the mobile
picker). See migrations `0099_ambassadorcohort_customuser_ambassador_cohort` and
`0100_backfill_ambassador_cohorts` - the latter is a pure data migration that
never writes to `is_ambassador`.

## The backfill (2026-09)

There was no clean historical record of which cohort each ambassador belonged to.
The backfill migration used the only two verifiable facts available:

- `is_ambassador=True` today -> Cohort 3 (the in-app Ambassador Info screen states
  Cohort 3 runs April 1 - September 30).
- `is_ambassador=False` but has at least one `AmbassadorMonthlyReport` -> a former
  ambassador (only an ambassador could ever submit one), previously in Cohort 1 or
  2, but which of the two can't be determined from existing data. Bucketed
  together into a single placeholder, `AmbassadorCohort(cohort_number=1, name=
  "Cohort 1-2 (Legacy, pre-tracking)")`.

If a real list distinguishing Cohort 1 from Cohort 2 ever turns up, split it via
the bulk-assign admin action described below - nothing about this design prevents
that later.

## Admin usage

- **Single user**: `CustomUserAdmin`'s edit page has `ambassador_cohort` right
  next to `is_ambassador` in the Permissions fieldset - set both when onboarding
  a new ambassador, or just the cohort on its own for anyone else.
- **Bulk-assign a list of approved users to a cohort**: create the cohort first
  (register it in the `AmbassadorCohort` admin - `cohort_number`, `name`,
  `start_date`/`end_date`, `status`), then select the target users in the
  `CustomUser` list and run the dynamically-generated action
  **"📚 Assign selected users to Cohort N"** (`CustomUserAdmin.get_actions` adds
  one such action per existing cohort automatically - a new cohort gets its
  action with no code change).
- Assigning a cohort never flips `is_ambassador`, and `make_ambassador`/
  `revoke_ambassador` never touch `ambassador_cohort` - run whichever action(s)
  you actually need.

## Brevo sync

`sync_contact_to_brevo` (`authentication/services/brevo_service.py`) sends these
attributes for this:

- `IS_AMBASSADOR` (boolean) - current status; mirrors `is_ambassador` exactly,
  preserving active payment/reward eligibility.
- `EVER_AMBASSADOR` (boolean) - current status OR a non-null cohort membership;
  historical targeting for past and present ambassadors, including those with zero referrals.
- `AMBASSADOR_COHORT` (integer, nullable) - the user's `ambassador_cohort.cohort_number`,
  or `null` if unassigned.
- `REFERRAL_COUNT` (integer) - how many users signed up with this user as referrer.
- `REFERRAL_SEGMENT` (string, nullable) - `"apply"` / `"forward"` / `null`. See
  the Referral segments section below - `null` whenever `REFERRAL_COUNT` is 0
  (there's no campaign message for someone who hasn't referred anyone).

This lets Brevo segments target e.g. "Ambassadors, Cohort 3" distinct from
"Cohort 4," "everyone ever in Cohort 1" regardless of current `is_ambassador`
status, or `REFERRAL_SEGMENT = apply` directly - no CSV re-export needed per
campaign. Ensure these attributes exist in the account contact attribute schema
before syncing.

## Referral segments (Ambassador Cohort 4 outreach, 2026-09)

Two mutually-exclusive, jointly-exhaustive segments over everyone who's ever
referred at least one person - added as `CustomUserQuerySet` methods
(`models.py`), reusable for future campaigns rather than a one-off script:

- **`CustomUser.objects.users_referred_never_ambassador()`** ("apply" message) -
  `referral_count > 0`, `is_ambassador=False`, AND `ambassador_cohort` is null
  (never assigned one, so genuinely never an ambassador - not just currently
  inactive).
- **`CustomUser.objects.users_referred_and_ambassador()`** ("forward" message) -
  `referral_count > 0` AND (`is_ambassador=True` OR has an `ambassador_cohort` on
  record). Deliberately checks `ambassador_cohort`, not just `is_ambassador` - a
  former ambassador whose status was later revoked keeps their cohort record
  (see the backfill section above), so they still get told "you know what it
  takes," not "you should apply" as if they'd never done it.

Both depend on `REFERRAL_COUNT` and ambassador history together - a user with
`referral_count=0` lands in neither, same as `REFERRAL_SEGMENT=null` above.
Verified mutually exclusive and jointly exhaustive in
`test_ambassador_referral_segments.py`.

Exposed as compose-screen segments too (not just Brevo attributes) - see
`_build_admin_user_queryset`'s `referral_segment=apply|forward` param and
`AdminSendEmailScreen.js`'s "Referred, Never Ambassador" / "Referred, Ever
Ambassador" segment chips - so a campaign can be sent directly from the mobile
admin tool the same day, without waiting on a full Brevo sync cycle or a manual
CSV import.

## Mobile compose screen (Email/Push)

`AdminSendEmailScreen.js`'s recipient-segment picker fetches the live cohort list
from `GET /api/admin/ambassador-cohorts/` on mount and folds it into the
"Ambassadors" pill as a sub-picker (same collapsed-group pattern as "New Users"/
"Referred Recently") - tapping it shows **All Ambassadors** (current
`is_ambassador=True`) plus one option per cohort. Selecting a cohort filters
recipients by `ambassador_cohort=N` alone (not ANDed with `is_ambassador=True`),
since a cohort-targeted send is often meant to reach a cohort's members
regardless of whether they're still active ambassadors today.


## Ever Ambassador targeting

In mobile admin compose, select **Ambassadors → Ever Ambassador** to email
past and current ambassadors, regardless of referral count. The shared recipient
filter uses `ever_ambassador=true` and `CustomUser.objects.ever_ambassador()`;
existing subscription, delivery and deletion exclusions still apply.

`revoke_user_ambassador_status()` explicitly resets `is_ambassador=False` and
preserves the cohort. The two ambassador flags therefore are not equivalent.
Historical coverage relies on cohort assignments being retained and the existing
backfill having run; an unrecorded former membership cannot be inferred.

Segment A now excludes the shared `ever_ambassador()` queryset. Its previous
implementation already excluded non-null cohorts, so this refactor changes no
membership for the same data. Actual overlap with the last two sends requires
production recipient logs; local regression tests cannot establish who received them.

Before Brevo targeting, ensure `EVER_AMBASSADOR` exists as a boolean contact
attribute in Brevo and run the existing contact sync to backfill it. The sync
command resumes from `brevo_sync_progress.txt`: archive/reset that checkpoint
before a full backfill so previously synced contacts receive the new attribute.
No database migration is needed for this derived attribute.
