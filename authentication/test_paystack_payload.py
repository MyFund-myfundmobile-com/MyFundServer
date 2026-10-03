from unittest import TestCase
from .services.paystack_payload import get_plan_code

class PaystackPlanPayloadTest(TestCase):
    def test_supported_recurring_charge_shapes(self):
        for data in ({'plan':'PLN_daily'}, {'plan':{'plan_code':'PLN_daily'}},
                     {'plan':{},'plan_object':{'plan_code':'PLN_daily'}},
                     {'plan':None,'plan_object':{'plan_code':'PLN_daily'}}):
            with self.subTest(data=data):
                self.assertEqual(get_plan_code(data),'PLN_daily')

    def test_one_off_or_invalid_plan_does_not_become_recurring(self):
        for data in ({},{'plan':None},{'plan':12},{'plan':'unrecognised'},{'plan':{'plan_code':3}}):
            with self.subTest(data=data):
                self.assertIsNone(get_plan_code(data))

from unittest.mock import patch
from django.test import TestCase as DjangoTestCase
from .models import AutoSave, CustomUser, Transaction
from .views import paystack_webhook_processing

class RecurringChargeReplayTest(DjangoTestCase):
    def test_string_plan_credits_once_and_replay_preserves_balance_snapshot(self):
        user = CustomUser.objects.create_user(email='autosave-test@example.com',phone_number='09000000042',password='test')
        AutoSave.objects.create(user=user,amount=200,frequency='daily',active=True,paystack_plan_code='PLN_daily')
        event={'event':'charge.success','data':{'reference':'recurring-test-reference','channel':'card','customer':{'email':user.email},'amount':20000,'plan':'PLN_daily','authorization':{}}}
        with patch('authentication.views.send_transactional_email'), patch('authentication.views.send_push_notification'), patch('authentication.views.save_or_update_card_from_paystack_auth'), patch('builtins.print'):
            paystack_webhook_processing(event,'127.0.0.1',True,{})
            user.refresh_from_db()
            self.assertEqual(user.savings,200)
            paystack_webhook_processing(event,'127.0.0.1',True,{})
        user.refresh_from_db()
        self.assertEqual(user.savings,200)
        tx=Transaction.objects.get(transaction_id='recurring-test-reference')
        self.assertEqual(tx.balance_before,0)
        self.assertEqual(tx.balance_after,200)
