from datetime import timedelta
from unittest.mock import MagicMock, patch
from django.core.files.uploadedfile import SimpleUploadedFile

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import AmbassadorIntake, AmbassadorApplication, CustomUser

INF = "/api/influencer/applications"
AMB = "/api/ambassador/applications"
INFLUENCER_COMPLETE = {
    "full_name": "Ada Creator", "age": "24", "phone": "08031234567", "location": "Yaba, Lagos",
    "has_account": "Yes", "was_ambassador": "No",
    "platforms": ["Instagram", "TikTok"], "link_instagram": "https://instagram.com/ada",
    "link_tiktok": "https://tiktok.com/@ada", "total_followers": "10K–50K", "niche": "Personal finance",
    "why_influencer": "I teach my followers to save every week.",
    "content_ideas": "A weekly #SaveWithAda series showing my MyFund target savings.",
    "monthly_content": "8", "monthly_signups": "20", "monthly_savers": "10", "has_brand_deals": "No",
    "follow_confirmed": True, "ongoing_role": "Yes", "disclose_partnership": "Yes",
    "contact_method": "WhatsApp", "tshirt_size": "M",
}


@patch("authentication.ambassador_application_views._run_in_background", lambda fn: fn())
@patch("authentication.utils.send_push_notification")
class InfluencerPortalTest(TestCase):
    def setUp(self):
        now = timezone.now()
        window = dict(opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=30), active=True)
        self.amb = AmbassadorIntake.objects.create(slug="amb", title="Cohort", programme="ambassador", **window)
        self.inf = AmbassadorIntake.objects.create(slug="inf", title="Influencers", programme="influencer", **window)
        mk = lambda email, phone, **extra: CustomUser.objects.create_user(email=email, password="Secret#123", first_name="Ada", last_name="C", phone_number=phone, **extra)
        self.team = mk("tolulopeahmed@gmail.com", "08032000001", is_staff=True)
        self.team.expo_push_tokens = [{"token": "ExponentPushToken[x]"}]
        self.team.save(update_fields=["expo_push_tokens"])
        mk("ada@example.com", "08032000002")
        self.client = APIClient()

    def sign_in(self, base):
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(f"{base}/password/", {"email": "ada@example.com", "password": "Secret#123", "privacy_accepted": True}, format="json")
        self.assertEqual(res.status_code, 200, res.data)
        return res.data

    def test_config_serves_influencer_questions(self, push):
        data = self.client.get(f"{INF}/config/").data
        self.assertEqual(data["intake"]["programme"], "influencer")
        keys = [f["key"] for step in data["steps"] for f in step["fields"]]
        self.assertIn("why_influencer", keys)
        self.assertNotIn("weekly_meetings", keys)
        self.assertEqual(self.client.get(f"{AMB}/config/").data["intake"]["programme"], "ambassador")

    def test_full_flow_is_separate_from_ambassador(self, push):
        data = self.sign_in(INF)
        app = AmbassadorApplication.objects.get(pk=data["application"]["id"])
        self.assertEqual(app.intake, self.inf)
        # Prefill only uses questions the influencer form asks.
        self.assertNotIn("has_saved", app.answers)
        self.assertEqual(app.answers["was_ambassador"], "No")
        self.assertIn("Influencer application started", push.call_args.kwargs["title"])

        auth = f"Application {data['token']}"
        # The influencer token can't open the ambassador application.
        self.assertEqual(self.client.get(f"{AMB}/draft/", HTTP_AUTHORIZATION=auth).status_code, 403)
        save = self.client.patch(f"{INF}/draft/", {"answers": INFLUENCER_COMPLETE, "step": 4, "revision": data["application"]["revision"]}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(save.status_code, 200, save.data)
        self.assertEqual(save.data["application"]["progress"], 100)
        with self.captureOnCommitCallbacks(execute=True):
            sub = self.client.post(f"{INF}/submit/", {"revision": save.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(sub.status_code, 200, sub.data)
        self.assertEqual(sub.data["application"]["status"], "submitted")
        self.assertIn("Influencer application submitted", push.call_args.kwargs["title"])
        self.assertIn("Started: 1 · Completed: 1", push.call_args.kwargs["message"])

        # An ambassador application for the same email is its own record.
        amb = self.sign_in(AMB)
        self.assertNotEqual(amb["application"]["id"], data["application"]["id"])

    def test_platform_links_required_only_when_picked(self, push):
        data = self.sign_in(INF)
        answers = {**INFLUENCER_COMPLETE, "platforms": ["Instagram", "YouTube"]}
        save = self.client.patch(f"{INF}/draft/", {"answers": answers, "step": 4, "revision": data["application"]["revision"]}, format="json", HTTP_AUTHORIZATION=f"Application {data['token']}")
        sub = self.client.post(f"{INF}/submit/", {"revision": save.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=f"Application {data['token']}")
        self.assertEqual(sub.status_code, 400)
        self.assertIn("link_youtube", sub.data["fields"])
        self.assertNotIn("link_x", sub.data["fields"])

    def test_requests_and_segments_split_by_programme(self, push):
        self.sign_in(INF)
        AmbassadorApplication.objects.create(intake=self.amb, email="amb@example.com")
        self.client.force_authenticate(user=self.team)
        inf = self.client.get("/api/admin/requests/", {"kind": "influencer_portal", "scope": "all"}).data
        self.assertEqual([r["email"] for r in inf["results"]], ["ada@example.com"])
        self.assertEqual(inf["results"][0]["kind"], "influencer_portal")
        amb = self.client.get("/api/admin/requests/", {"kind": "ambassador", "scope": "all"}).data
        self.assertEqual([r["email"] for r in amb["results"]], ["amb@example.com"])
        emails = self.client.get("/api/admin/users/emails/", {"influencer_application": "all"}).data
        self.assertEqual(emails["filters_applied"]["influencer_application"], "all")
        link = self.client.post("/api/admin/requests/ambassador/export-link/", {"programme": "influencer"}, format="json")
        self.client.force_authenticate(user=None)
        csv = self.client.get(link.data["url"].split("testserver")[1])
        self.assertEqual(csv.status_code, 200)
        self.assertIn("myfund-influencer-applications", csv["Content-Disposition"])
        self.assertIn("Why do you want to be a MyFund Influencer?", csv.content.decode())

    def test_must_confirm_following_myfund(self, push):
        data = self.sign_in(INF)
        auth = f"Application {data['token']}"
        config = self.client.get(f"{INF}/config/").data
        fields = {f["key"]: f for step in config["steps"] for f in step["fields"]}
        self.assertEqual(fields["link_instagram"]["follow"], "https://instagram.com/myfundmobile1")
        self.assertIn("TikTok", fields["follow_confirmed"]["follow_all"])
        save = self.client.patch(f"{INF}/draft/", {"answers": {**INFLUENCER_COMPLETE, "follow_confirmed": False}, "step": 4, "revision": data["application"]["revision"]}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertLess(save.data["application"]["progress"], 100)
        sub = self.client.post(f"{INF}/submit/", {"revision": save.data["application"]["revision"], "confirmed": True}, format="json", HTTP_AUTHORIZATION=auth)
        self.assertEqual(sub.status_code, 400)
        self.assertIn("follow_confirmed", sub.data["fields"])


def fake_imagekit(private_in_details):
    """ImageKit as it really behaves: the upload response omits
    isPrivateFile (SDK reports False); the file details carry the truth."""
    kit = MagicMock()
    kit.upload.return_value = MagicMock(file_id="f1", file_path="/influencer-applications/v.webm", is_private_file=False)
    kit.get_file_details.return_value.response_metadata.raw = {"isPrivateFile": private_in_details}
    kit.url.return_value = "https://ik.imagekit.io/myfundmobile/signed"
    return kit


@patch("authentication.ambassador_application_views._run_in_background", lambda fn: None)
class ApplicationVideoUploadTest(TestCase):
    def setUp(self):
        now = timezone.now()
        intake = AmbassadorIntake.objects.create(slug="inf", title="Influencers", programme="influencer",
                                                 opens_at=now - timedelta(days=1), closes_at=now + timedelta(days=30), active=True)
        self.app = AmbassadorApplication.objects.create(intake=intake, email="vid@example.com")
        from .ambassador_application_views import application_token
        self.auth = f"Application {application_token(self.app)}"
        self.client = APIClient()

    def upload(self, kit):
        video = SimpleUploadedFile("myfund-introduction.webm", b"\x1aE\xdf\xa3" + b"0" * 64, content_type="video/webm")
        with patch("utils.imageKit.imagekit", kit):
            return self.client.post(f"{INF}/video/?revision=0", {"video": video}, HTTP_AUTHORIZATION=self.auth)

    def test_private_upload_is_accepted(self):
        kit = fake_imagekit(True)
        res = self.upload(kit)
        self.assertEqual(res.status_code, 200, res.data)
        self.app.refresh_from_db()
        self.assertEqual(self.app.video_file_id, "f1")
        kit.upload.assert_called_once()
        self.assertEqual(kit.upload.call_args.kwargs["options"].folder, "/influencer-applications")

    def test_public_upload_is_rejected_and_removed(self):
        kit = fake_imagekit(False)
        res = self.upload(kit)
        self.assertEqual(res.status_code, 503)
        kit.delete_file.assert_called_once_with("f1")
        self.app.refresh_from_db()
        self.assertEqual(self.app.video_file_id, "")
