import datetime
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from .models import CustomUser, Transaction
from .savings_statement import build_statement, wealth_stage
from .statement_models import SavingsStatement


class WealthStageTest(TestCase):
    def test_matches_app_thresholds(self):
        self.assertEqual(wealth_stage(0, 0, 0)["stage"], 1)
        self.assertEqual(wealth_stage(500, 0, 0)["stage"], 2)
        self.assertEqual(wealth_stage(100_000, 0, 0)["stage"], 3)
        self.assertEqual(wealth_stage(0, 1, 0)["stage"], 3)
        self.assertEqual(wealth_stage(200_000, 100_001, 0)["stage"], 4)
        self.assertEqual(wealth_stage(1_000_000, 0, 0)["stage"], 5)
        self.assertEqual(wealth_stage(2_000_000, 0, 0)["stage"], 6)
        self.assertEqual(wealth_stage(1_000_000, 0, 100_000)["stage"], 7)
        self.assertEqual(wealth_stage(1_000_000, 0, 500_000)["stage"], 8)
        self.assertEqual(wealth_stage(1_000_000, 0, 1_000_000)["stage"], 9)

    def test_stage_one_never_says_debt(self):
        self.assertEqual(wealth_stage(0, 0, 0)["name"], "Starter")


class StatementTest(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(email="saver@example.com", phone_number="08000000001",
                                                   password="x", first_name="ada", last_name="obi")
        CustomUser.objects.filter(pk=self.user.pk).update(savings=Decimal("150000"), kyc_status="approved")
        self.user.refresh_from_db()

    def tx(self, kind, amount, description, source=None, credited_to=None, ref=None, when=None):
        t = Transaction.objects.create(user=self.user, transaction_type=kind, amount=Decimal(amount),
                                       description=description, status="confirmed", source=source,
                                       credited_to=credited_to, **({"transaction_id": ref} if ref else {}))
        if when:
            Transaction.objects.filter(pk=t.pk).update(date=when)
        return t

    def test_counts_real_deposits_not_own_account_moves(self):
        self.tx("credit", "20000", "QuickSave (Card)", source="CARD", credited_to="SAVINGS")
        self.tx("credit", "5000", "AutoSave (Daily)", credited_to="SAVINGS")
        # Wallet > Savings pair (new style, by reference)
        self.tx("debit", "7000", "Wallet > Savings", source="WALLET", ref="abc-D")
        self.tx("credit", "7000", "QuickSave (Transfer)", credited_to="SAVINGS", ref="abc-C")
        # Savings > Investment pair (old style, no reference: matched by amount + time)
        self.tx("debit", "3000", "Savings > Investment", source="SAVINGS")
        self.tx("credit", "3000", "QuickInvest", credited_to="INVESTMENT")
        self.tx("debit", "4000", "Savings > Bank", source="SAVINGS")
        self.tx("credit", "1000", "Dividends: Q3 2026 ROI", credited_to="WALLET")
        self.tx("debit", "100", "WHT|Q3 2026|10%", source="WALLET")
        Transaction.objects.create(user=self.user, transaction_type="credit", amount=Decimal("99999"),
                                   description="QuickSave (Card)", status="failed", credited_to="SAVINGS")

        data = build_statement(self.user, 3)
        self.assertEqual(Decimal(data["totals"]["money_in"]), Decimal("25000"))
        self.assertEqual(Decimal(data["totals"]["withdrawn"]), Decimal("4000"))
        self.assertEqual(Decimal(data["totals"]["returns"]), Decimal("900"))
        self.assertEqual(Decimal(data["totals"]["net_saved"]), Decimal("21000"))
        self.assertEqual(data["stage"]["stage"], 3)
        self.assertEqual(data["name"], "Ada Obi")
        self.assertTrue(data["kyc_verified"])
        self.assertEqual(len(data["monthly"]), 3)
        self.assertEqual(len(data["transactions"]), 9)  # failed one left out

    def test_old_transactions_outside_period_ignored(self):
        self.tx("credit", "50000", "QuickSave (Card)", source="CARD", credited_to="SAVINGS",
                when=timezone.now() - datetime.timedelta(days=400))
        self.assertEqual(Decimal(build_statement(self.user, 12)["totals"]["money_in"]), Decimal("0"))

    def test_download_issues_pdf_and_verify_shows_figures(self):
        self.tx("credit", "20000", "QuickSave (Card)", source="CARD", credited_to="SAVINGS")
        client = APIClient()
        client.force_authenticate(self.user)
        res = client.get("/api/savings-statement/?months=6")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res["Content-Type"], "application/pdf")
        self.assertTrue(res.content.startswith(b"%PDF"))
        statement = SavingsStatement.objects.get(user=self.user)
        self.assertIn(statement.code, res["Content-Disposition"])

        public = APIClient().get(f"/api/savings-statement/verify/{statement.code.lower()}/")
        self.assertEqual(public.status_code, 200)
        self.assertTrue(public.data["valid"])
        self.assertEqual(public.data["name"], "Ada Obi")
        self.assertEqual(public.data["totals"]["money_in"], "20000.00")
        self.assertNotIn("email", public.data)
        statement.refresh_from_db()
        self.assertEqual(statement.verify_count, 1)

    def test_rejects_bad_period_and_unknown_code(self):
        client = APIClient()
        client.force_authenticate(self.user)
        self.assertEqual(client.get("/api/savings-statement/?months=5").status_code, 400)
        self.assertEqual(APIClient().get("/api/savings-statement/verify/MFS-XXXXX-XXXXX/").status_code, 404)
        self.assertEqual(APIClient().get("/api/savings-statement/?months=6").status_code, 401)


class DisciplineAndStoryTest(TestCase):
    def test_discipline_levels(self):
        from .savings_statement import discipline_level
        self.assertEqual(discipline_level(5, 6, Decimal(100), Decimal(20), 12)["level"], "Strong")
        self.assertEqual(discipline_level(5, 6, Decimal(100), Decimal(20), 3)["level"], "Good")  # too new
        self.assertEqual(discipline_level(3, 6, Decimal(100), Decimal(70), 12)["level"], "Good")
        self.assertEqual(discipline_level(1, 6, Decimal(100), Decimal(90), 12)["level"], "Building")
        self.assertEqual(discipline_level(0, 6, Decimal(0), Decimal(0), 12)["level"], "Not yet rated")
        self.assertEqual(discipline_level(5, 6, Decimal(100), Decimal(20), 12)["kept_pct"], 80)

    def test_tenure_wording(self):
        from .savings_statement import _tenure
        self.assertEqual(_tenure(datetime.date(2025, 4, 1), datetime.date(2026, 11, 8))[0], "1 year and 7 months")
        self.assertEqual(_tenure(datetime.date(2026, 10, 1), datetime.date(2026, 11, 8))[0], "1 month")

    def test_headline_reads_like_a_story(self):
        user = CustomUser.objects.create_user(email="s2@example.com", phone_number="08000000002", password="x",
                                              first_name="tolu")
        CustomUser.objects.filter(pk=user.pk).update(savings=Decimal("5000000"), wallet=Decimal("622699"))
        user.refresh_from_db()
        Transaction.objects.create(user=user, transaction_type="credit", amount=Decimal("963998"),
                                   description="Dividends: Q3 2026 ROI", status="confirmed", credited_to="WALLET")
        data = build_statement(user, 6)
        self.assertTrue(data["highlights"][0].startswith("In "))
        self.assertIn("Tolu has built NGN 5,622,699 with MyFund and earned NGN 963,998 in dividends.",
                      data["highlights"][0])


class PreviewTest(TestCase):
    def test_preview_issues_nothing(self):
        user = CustomUser.objects.create_user(email="p@example.com", phone_number="08000000003", password="x")
        client = APIClient()
        client.force_authenticate(user)
        res = client.get("/api/savings-statement/preview/?months=12")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["months"], 12)
        self.assertIn("discipline", res.data)
        self.assertEqual(len(res.data["monthly"]), 12)
        self.assertFalse(SavingsStatement.objects.exists())
        self.assertEqual(client.get("/api/savings-statement/preview/?months=7").status_code, 400)
