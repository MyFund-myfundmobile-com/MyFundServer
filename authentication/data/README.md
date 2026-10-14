# Cohort 4 personality recommendations

Source: `Cohort4_Ambassador_Roles_Courses.xlsx`, supplied October 2026.
The JSON preserves the 18 completed rows, both recommended courses, and the
recommended role including any extra internship suggestion. Blank-result rows
are deliberately omitted. Personality summaries are original short guidance;
type names follow https://www.16personalities.com/personality-types.

The file is server-only. `TopReferralsAPIView` resolves the authenticated
requester's record and returns it separately from leaderboard rows. Do not
include these records in generic user serializers or the mobile bundle.
The mobile app holds the result only in the screen's local state.

Account IDs were matched against the live Cohort 4 roster using read-only
queries. The owner confirmed these three name differences on October 14, 2026:

- Ukanah Peter: Sunday Ukanah, account 389.
- Olowookere Praise: Praise Ayomide, account 655.
- Abulu Judith: Osehuemome Abulu, account 1108.

All 18 completed profiles are assigned. Praise's result is INFJ; do not
invent an A/T subtype. Future entries require a verified account match.

Deploy the backend and ship the updated mobile app. No database migration or
production-data write is required. Older app versions ignore the new fields;
new app versions hide the chip until the backend returns a profile.

Validation: `python -m unittest authentication.test_ambassador_personality`;
endpoint privacy tests are in `authentication.test_top_referrals_roles`.
Local SQLite integration tests require migrations disabled in the temporary
test runner because existing migrations contain PostgreSQL-only SQL.

Christine Ahsan (account 1443, company@myfundmobile.com) was added by direct
owner instruction on October 14, 2026 as Commander (ENTJ-A), with Assertive confirmed by the owner. Courses
and internship role were not supplied. There are now 19 assigned profiles.
