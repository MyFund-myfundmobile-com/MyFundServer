from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from .models import CustomUser, GroupBuyInterest, Property


def mk(email, phone, **extra):
    return CustomUser.objects.create_user(email=email, password="x", first_name="T", last_name="U", phone_number=phone, **extra)


class GroupBuyInterestTest(TestCase):
    def setUp(self):
        self.user = mk("buyer@example.com", "08031110001")
        self.prop = Property.objects.create(name="Ogbomoso Hostel", description="d", price=1000000, rent_reward=50000, units_available=0)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def register(self, **body):
        return self.client.post(f"/api/groupbuy-interest/{self.prop.id}/", {"interests": ["co_own"], "budget": "100k_500k", **body}, format="json")

    @patch("authentication.ambassador_application_views._run_in_background", side_effect=lambda fn: fn())
    @patch("authentication.groupbuy_interest._notify_team")
    def test_first_registration_alerts_team_once(self, notify, _bg):
        with self.captureOnCommitCallbacks(execute=True):
            res = self.register()
        self.assertEqual(res.status_code, 201)
        with self.captureOnCommitCallbacks(execute=True):
            res = self.register(interests=["co_own", "rental_income"], budget="500k_2m")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(GroupBuyInterest.objects.get().interests, ["co_own", "rental_income"])
        self.assertEqual(notify.call_count, 1)

    def test_needs_a_valid_choice(self):
        self.assertEqual(self.register(interests=[]).status_code, 400)
        self.assertEqual(self.register(interests=["nonsense"]).status_code, 400)
        self.assertEqual(self.register(budget="a lot").status_code, 400)

    @patch("authentication.utils.send_push_notification")
    def test_push_goes_to_janet_tolulope_and_chubi(self, push):
        team = [mk(e, f"0803222000{i}", expo_push_tokens=["ExponentPushToken[x]"])
                for i, e in enumerate(["tolulopeahmed@gmail.com", "janet.adegbenro@gmail.com", "josephgideon95@gmail.com"])]
        mk("someone.else@example.com", "08032220009")
        from .groupbuy_interest import _notify_team
        _notify_team(GroupBuyInterest.objects.create(user=self.user, property=self.prop, interests=["live_in"]))
        self.assertEqual(sorted(c.kwargs["user"].email for c in push.call_args_list), sorted(u.email for u in team))
        self.assertIn("Ogbomoso Hostel", push.call_args.kwargs["message"])

    def test_my_interests_and_admin_list(self):
        self.register()
        mine = self.client.get("/api/groupbuy-interest/").data
        self.assertEqual(mine["interests"][0]["property_id"], self.prop.id)
        self.assertEqual(self.client.get("/api/admin/groupbuy-interests/").status_code, 403)
        staff = mk("staff@example.com", "08031110002", is_staff=True)
        self.client.force_authenticate(staff)
        data = self.client.get("/api/admin/groupbuy-interests/").data
        self.assertEqual(data["properties"][0]["total"], 1)
        self.assertEqual(data["results"][0]["interests"], ["Co-own a share"])
