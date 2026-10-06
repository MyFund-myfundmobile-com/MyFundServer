from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import AmbassadorIntake

BASE = "/api/ambassador/applications"

COMPLETE = {
    "full_name": "Ada Lovelace", "age": "24", "phone": "+234 803 000 0000",
    "location": "Ikeja, Lagos", "occupation": "Working Professional",
    "has_account": "No", "has_saved": "No",
    "communities": ["Church", "WhatsApp"], "weekly_reach": "100–300",
    "social_link": "https://instagram.com/ada", "has_promoted": "No",
    "motivation": "I want my friends to build a saving habit.",
    "saving_habits": "I save occasionally", "products": ["Savings"],
    "signup_target": "20", "growth_plan": "Weekly WhatsApp sessions with my church group.",
    "six_months": "Yes", "weekly_meetings": "Yes", "monthly_targets": "Yes",
}


@patch("authentication.ambassador_application_views.send_transactional_email", return_value={"status": "completed", "sent": 1})
class AmbassadorApplicationFlowTest(TestCase):
    def setUp(self):
        now = timezone.now()
        AmbassadorIntake.objects.create(
            slug="october-2026", title="October 2026 – March 2027",
            opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=5), active=True,
        )
        self.client = APIClient()

    def start(self):
        with patch("authentication.ambassador_application_views.secrets.randbelow", return_value=123456):
            res = self.client.post(f"{BASE}/code/", {"email": "ada@example.com", "privacy_accepted": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        res = self.client.post(f"{BASE}/verify/", {"challenge": res.data["challenge"], "code": "123456"}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        return f"Application {res.data['token']}", res.data["application"]

    def save(self, auth, app, answers):
        return self.client.patch(f"{BASE}/draft/", {"answers": answers, "step": 0, "revision": app["revision"]}, format="json", HTTP_AUTHORIZATION=auth)

    def test_config_has_the_trimmed_question_set(self, _):
        keys = [f["key"] for step in self.client.get(f"{BASE}/config/").data["steps"] for f in step["fields"]]
        for added in ("location", "social_link", "motivation"):
            self.assertIn(added, keys)
        for removed in ("persuasion_example", "expected_savers", "growth_ideas", "skill_courses", "financial_discipline"):
            self.assertNotIn(removed, keys)

    def test_full_flow_draft_then_submit(self, _):
        auth, app = self.start()
        res = self.save(auth, app, COMPLETE)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(res.data["application"]["progress"], 100)
        res = self.client.post(f"{BASE}/submit/", {"revision": res.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertNotEqual(res.data["application"]["status"], "draft")

    def test_submit_rejects_under_18_and_non_https_social_link(self, _):
        # Drafts deliberately keep half-typed answers (autosave); the strict
        # checks run on submit.
        auth, app = self.start()
        res = self.save(auth, app, {**COMPLETE, "age": "17", "social_link": "instagram.com/ada"})
        self.assertEqual(res.status_code, 200, res.data)
        res = self.client.post(f"{BASE}/submit/", {"revision": res.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(res.status_code, 400)
        self.assertIn("age", res.data.get("fields", {}))
        self.assertIn("social_link", res.data.get("fields", {}))

    def test_submit_requires_location(self, _):
        auth, app = self.start()
        res = self.save(auth, app, {k: v for k, v in COMPLETE.items() if k != "location"})
        self.assertEqual(res.status_code, 200, res.data)
        res = self.client.post(f"{BASE}/submit/", {"revision": res.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(res.status_code, 400)
        self.assertIn("location", res.data.get("fields", {}))


class MemberPasswordSignInTest(TestCase):
    """Existing MyFund members skip the emailed code and use their password."""

    def setUp(self):
        from django.core.cache import cache
        from .models import CustomUser
        cache.clear()
        now = timezone.now()
        AmbassadorIntake.objects.create(
            slug="october-2026", title="October 2026 – March 2027",
            opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=5), active=True,
        )
        self.user = CustomUser.objects.create_user(
            email="member@example.com", password="Secret#123", first_name="Ada Grace",
            last_name="Okafor", phone_number="08031234567",
        )
        self.client = APIClient()

    def test_lookup_reveals_only_first_name_for_members(self):
        res = self.client.post(f"{BASE}/lookup/", {"email": "Member@Example.com"}, format="json")
        self.assertEqual(res.data, {"member": True, "first_name": "Ada"})
        res = self.client.post(f"{BASE}/lookup/", {"email": "stranger@example.com"}, format="json")
        self.assertEqual(res.data, {"member": False})

    def test_password_sign_in_opens_prefilled_application(self):
        res = self.client.post(f"{BASE}/password/", {"email": "member@example.com", "password": "Secret#123", "privacy_accepted": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertTrue(res.data["token"])
        self.assertEqual(res.data["application"]["answers"].get("has_account"), "Yes")
        self.assertTrue(res.data["application"]["reminder_consent"])  # on by default, no checkbox

    def test_wrong_password_and_missing_privacy_are_refused(self):
        bad = self.client.post(f"{BASE}/password/", {"email": "member@example.com", "password": "nope", "privacy_accepted": True}, format="json")
        self.assertEqual(bad.status_code, 400)
        self.assertNotIn("token", bad.data)
        no_privacy = self.client.post(f"{BASE}/password/", {"email": "member@example.com", "password": "Secret#123"}, format="json")
        self.assertEqual(no_privacy.status_code, 400)

    def test_password_attempts_are_rate_limited_per_email(self):
        for _ in range(8):
            self.client.post(f"{BASE}/password/", {"email": "member@example.com", "password": "nope", "privacy_accepted": True}, format="json")
        res = self.client.post(f"{BASE}/password/", {"email": "member@example.com", "password": "Secret#123", "privacy_accepted": True}, format="json")
        self.assertEqual(res.status_code, 429)


@patch("authentication.ambassador_application_views._run_in_background", lambda fn: fn())
@patch("authentication.utils.send_push_notification")
class ApplicationTeamPushTest(TestCase):
    """Tolulope, Janet and Chubi get a push when an application is started
    and when it's submitted - with the intake's started/completed totals."""

    def setUp(self):
        from django.core.cache import cache
        from .models import CustomUser
        cache.clear()
        now = timezone.now()
        AmbassadorIntake.objects.create(slug="october-2026", title="October 2026 – March 2027",
                                        opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=5), active=True)
        tokens = [{"token": "ExponentPushToken[x]"}]
        mk = lambda email, phone: CustomUser.objects.create_user(email=email, password="Secret#123", first_name="T", last_name="U", phone_number=phone)
        self.team = [mk("tolulopeahmed@gmail.com", "08030000011"), mk("janet.adegbenro@gmail.com", "08030000012"),
                     mk("josephgideon95@gmail.com", "08030000013")]
        self.outsider = mk("someone.else@example.com", "08030000015")
        for u in (*self.team, self.outsider):
            u.expo_push_tokens = tokens; u.save(update_fields=["expo_push_tokens"])
        self.applicant = mk("applicant@example.com", "08030000014")
        self.client = APIClient()

    def test_alert_flags_non_members(self, push):
        from authentication.ambassador_application_views import make_application
        intake = AmbassadorIntake.objects.get(slug="october-2026")
        with self.captureOnCommitCallbacks(execute=True):
            make_application(intake, "newcomer@example.com")
        self.assertIn("Not a MyFund user yet", push.call_args.kwargs["message"])

    def recipients(self, push):
        return sorted(c.kwargs["user"].email for c in push.call_args_list)

    def test_start_and_submit_alert_the_three_with_totals(self, push):
        team = sorted(u.email for u in self.team)
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(f"{BASE}/password/", {"email": "applicant@example.com", "password": "Secret#123", "privacy_accepted": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        self.assertEqual(self.recipients(push), team)
        self.assertIn("started", push.call_args.kwargs["title"])
        self.assertIn("Started: 1 · Completed: 0", push.call_args.kwargs["message"])
        self.assertIn("Existing MyFund user", push.call_args.kwargs["message"])

        push.reset_mock()
        auth = f"Application {res.data['token']}"
        save = self.client.patch(f"{BASE}/draft/", {"answers": COMPLETE, "step": 0, "revision": res.data["application"]["revision"]}, format="json", HTTP_AUTHORIZATION=auth)
        with self.captureOnCommitCallbacks(execute=True):
            sub = self.client.post(f"{BASE}/submit/", {"revision": save.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(sub.status_code, 200, sub.data)
        self.assertEqual(self.recipients(push), team)
        self.assertIn("submitted", push.call_args.kwargs["title"])
        self.assertIn("Ada Lovelace from Ikeja, Lagos", push.call_args.kwargs["message"])
        self.assertIn("Started: 1 · Completed: 1", push.call_args.kwargs["message"])
        self.assertIn("Existing MyFund user", push.call_args.kwargs["message"])

        push.reset_mock()  # a retried submit (lost response) must not re-alert
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(f"{BASE}/submit/", {"revision": save.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        push.assert_not_called()

    def test_resuming_an_existing_application_does_not_notify(self, push):
        body = {"email": "applicant@example.com", "password": "Secret#123", "privacy_accepted": True}
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(f"{BASE}/password/", body, format="json")
        push.reset_mock()
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(f"{BASE}/password/", body, format="json")
        push.assert_not_called()


class AmbassadorRequestsAdminTest(TestCase):
    """Admin -> Requests -> MyFund Ambassadors: founders-only list, details
    and CSV export of every application's answers."""

    def setUp(self):
        from .models import CustomUser, AmbassadorApplication
        now = timezone.now()
        intake = AmbassadorIntake.objects.create(slug="october-2026", title="October 2026 – March 2027",
                                                 opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=5), active=True)
        self.founder = CustomUser.objects.create_user(email="janet.adegbenro@gmail.com", password="x", first_name="J", last_name="A", phone_number="08030000021", is_staff=True)
        self.staff = CustomUser.objects.create_user(email="josephgideon95@gmail.com", password="x", first_name="C", last_name="G", phone_number="08030000022", is_staff=True)
        AmbassadorApplication.objects.create(intake=intake, email="ada@example.com", answers=COMPLETE, status="submitted", progress=100, submitted_at=now)
        AmbassadorApplication.objects.create(intake=intake, email="draft@example.com", answers={"full_name": "Dee Raft"}, progress=10)
        self.client = APIClient()

    def test_founder_sees_submitted_and_drafts_with_answers(self):
        self.client.force_authenticate(self.founder)
        pending = self.client.get("/api/admin/requests/", {"kind": "ambassador", "scope": "pending"}).data
        self.assertEqual([r["email"] for r in pending["results"]], ["ada@example.com"])
        self.assertEqual(pending["summary"], {"started": 2, "completed": 1})
        self.assertEqual(pending["counts"]["ambassador"], 1)
        labels = {r["label"]: r["value"] for r in pending["results"][0]["responses"]}
        self.assertEqual(labels["City and state"], "Ikeja, Lagos")
        everything = self.client.get("/api/admin/requests/", {"kind": "ambassador", "scope": "all"}).data
        self.assertEqual(everything["count"], 2)
        self.assertIn("In progress", [r["status_label"] for r in everything["results"]][-1] + [r["status_label"] for r in everything["results"]][0])

    def test_csv_export_for_founders_only_via_short_lived_link(self):
        self.client.force_authenticate(self.staff)  # Chubi gets alerts, not Requests access
        self.assertEqual(self.client.post("/api/admin/requests/ambassador/export-link/").status_code, 403)
        self.client.force_authenticate(self.founder)
        url = self.client.post("/api/admin/requests/ambassador/export-link/").data["url"]
        self.client.force_authenticate(None)
        res = self.client.get(url.split("testserver")[-1])
        self.assertEqual(res.status_code, 200)
        body = res.content.decode("utf-8-sig")
        self.assertIn("City and state", body.splitlines()[0])
        self.assertIn("Ikeja, Lagos", body)
        self.assertIn("draft@example.com", body)
        self.assertEqual(self.client.get("/api/admin/requests/ambassador/export/?token=forged").status_code, 403)
