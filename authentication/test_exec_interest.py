from types import SimpleNamespace
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from .exec_interest_models import ExecutiveInterest
from .models import AmbassadorCohort, CustomUser

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
ANSWER = "I have led my department's welfare team for two years."


def photo(content=PNG, name="me.png", kind="image/png"):
    return SimpleUploadedFile(name, content, content_type=kind)


@mock.patch("authentication.exec_interest.send_push_notification")
@mock.patch("authentication.exec_interest.send_transactional_email")
@mock.patch("authentication.exec_interest._upload_photo", return_value=("file1", "https://ik.imagekit.io/x/me.png"))
class ExecInterestTest(TestCase):
    def setUp(self):
        self.cohort = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        self.amb = CustomUser.objects.create_user(email="amb@example.com", phone_number="08000000001",
                                                  password="x", first_name="Ada", last_name="Obi")
        CustomUser.objects.filter(pk=self.amb.pk).update(is_ambassador=True, ambassador_cohort=self.cohort)
        self.client = APIClient()

    def post(self, **over):
        body = {"email": " AMB@example.com ", "role": "lead", "why_fit": ANSWER, "ideas": ANSWER,
                "why_vote": ANSWER, "photo": photo(), **over}
        body = {k: v for k, v in body.items() if v is not None}
        return self.client.post("/api/ambassador-exec/interest/", body, format="multipart")

    def test_ambassador_submits(self, upload, *_):
        res = self.post()
        self.assertEqual(res.status_code, 201, res.data)
        e = ExecutiveInterest.objects.get()
        self.assertEqual((e.user_id, e.cohort_id, e.role, e.photo_url),
                         (self.amb.id, self.cohort.id, "lead", "https://ik.imagekit.io/x/me.png"))
        self.assertEqual(res.data["role_name"], "Lead")

    def test_resubmitting_updates_and_keeps_photo(self, upload, *_):
        self.post()
        res = self.post(role="secretary", photo=None)
        self.assertEqual(res.status_code, 200, res.data)
        self.assertTrue(res.data["updated"])
        e = ExecutiveInterest.objects.get()
        self.assertEqual((e.role, e.photo_url), ("secretary", "https://ik.imagekit.io/x/me.png"))
        self.assertEqual(upload.call_count, 1)

    def test_rejections(self, upload, *_):
        self.assertEqual(self.post(email="nobody@example.com").status_code, 404)
        self.assertEqual(self.post(role="president").status_code, 400)
        self.assertEqual(self.post(ideas="ok").status_code, 400)
        self.assertEqual(self.post(photo=None).status_code, 400)  # photo needed first time
        self.assertFalse(ExecutiveInterest.objects.exists())

    def test_non_ambassador_refused(self, *_):
        CustomUser.objects.filter(pk=self.amb.pk).update(is_ambassador=False)
        self.assertEqual(self.post().status_code, 404)


@mock.patch("authentication.exec_interest.send_transactional_email")
@mock.patch("authentication.exec_interest._upload_photo", return_value=("file1", "https://ik.imagekit.io/x/me.png"))
@mock.patch("authentication.exec_interest._run_in_background", side_effect=lambda fn: fn())
@mock.patch("authentication.exec_interest.send_push_notification")
class StartedCompletedAlertsTest(TestCase):
    def setUp(self):
        self.cohort = AmbassadorCohort.objects.create(cohort_number=4, status="active")
        mk = lambda email, phone, **kw: CustomUser.objects.create_user(
            email=email, phone_number=phone, password="x", first_name=email.split("@")[0].title(),
            last_name="X", **kw)
        self.amb = mk("amb@example.com", "08000000001")
        self.amb2 = mk("amb2@example.com", "08000000002")
        CustomUser.objects.filter(pk__in=[self.amb.pk, self.amb2.pk]).update(
            is_ambassador=True, ambassador_cohort=self.cohort)
        self.team = [mk(e, f"0810000000{i}", expo_push_tokens=["ExponentPushToken[x]"])
                     for i, e in enumerate(["tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com",
                                            "josephgideon95@gmail.com"])]
        self.client = APIClient()

    def start(self, email="amb@example.com", **kw):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post("/api/ambassador-exec/start/", {"email": email, **kw}, format="json")

    def submit(self, email="amb@example.com"):
        body = {"email": email, "role": "lead", "why_fit": ANSWER, "ideas": ANSWER, "why_vote": ANSWER,
                "photo": photo()}
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post("/api/ambassador-exec/interest/", body, format="multipart")

    def messages(self, push):
        return [(c.kwargs["user"].email, c.kwargs["title"], c.kwargs["message"]) for c in push.call_args_list]

    def test_start_then_complete_alerts_team_with_counts(self, push, *_):
        res = self.start(role="lead")
        self.assertEqual(res.data["first_name"], "Amb")
        sent = self.messages(push)
        self.assertEqual({e for e, *_ in sent},
                         {"tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com", "josephgideon95@gmail.com"})
        self.assertEqual(sent[0][1], "Lead: interest started ✍️")
        self.assertIn("started their form for Lead. Started: 1 · Completed: 0", sent[0][2])

        self.start()  # coming back later doesn't re-alert
        self.assertEqual(push.call_count, 3)

        self.start(email="amb2@example.com")  # no role picked yet
        self.assertEqual(self.messages(push)[-1][1], "Executive interest started ✍️ (no role picked yet)")
        self.assertIn("Started: 2 · Completed: 0", self.messages(push)[-1][2])

        push.reset_mock()
        self.assertEqual(self.submit().status_code, 201)
        sent = self.messages(push)
        self.assertEqual(len(sent), 3)
        self.assertEqual(sent[0][1], "Lead: interest completed ✅")
        self.assertIn("completed their form for Lead. Started: 2 · Completed: 1", sent[0][2])

        push.reset_mock()
        self.submit()  # an update doesn't re-alert
        push.assert_not_called()

    def test_submit_without_start_counts_both(self, push, *_):
        self.submit()
        titles = [t for _, t, _ in self.messages(push)]
        self.assertEqual(titles.count("Lead: interest started ✍️"), 3)
        self.assertEqual(titles.count("Lead: interest completed ✅"), 3)
        self.assertIn("Started: 1 · Completed: 1", self.messages(push)[-1][2])

    def test_admin_list(self, *_):
        self.start(email="amb2@example.com")
        self.submit()
        staff = self.team[0]
        CustomUser.objects.filter(pk=staff.pk).update(is_staff=True)
        staff.refresh_from_db()
        self.client.force_authenticate(staff)
        data = self.client.get("/api/admin/exec-interests/").data
        self.assertEqual((data["started"], data["completed"]), (2, 1))
        self.assertEqual([r["status"] for r in data["results"]], ["completed", "started"])
        self.assertEqual(next(r for r in data["roles"] if r["role"] == "lead")["completed"], 1)
        self.client.force_authenticate(self.amb)
        self.assertEqual(self.client.get("/api/admin/exec-interests/").status_code, 403)

    def test_unknown_email_cannot_start(self, push, *_):
        self.assertEqual(self.start(email="nobody@example.com").status_code, 404)
        push.assert_not_called()


class PhotoCheckTest(TestCase):
    def test_rejects_non_images(self):
        from .exec_interest import _upload_photo
        user = SimpleNamespace(pk=1)
        with self.assertRaises(ValueError):
            _upload_photo(photo(b"%PDF-1.4" + b"\x00" * 64, "cv.pdf", "application/pdf"), user)
