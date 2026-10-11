from django.db import migrations
from django.db.models import Exists, OuterRef


def repair_completed_debits(apps, schema_editor):
    alias = schema_editor.connection.alias
    Withdrawal = apps.get_model('authentication', 'WithdrawalsRequestToAdmin')
    Transaction = apps.get_model('authentication', 'Transaction')
    completed = Withdrawal.objects.using(alias).filter(
        user_id=OuterRef('user_id'), transaction_id=OuterRef('transaction_id'),
        withdrawal_type='scheduled', is_processed=True, status='completed',
    )
    Transaction.objects.using(alias).filter(transaction_type='debit').filter(
        Exists(completed)
    ).update(status='confirmed', is_processed=True)


class Migration(migrations.Migration):
    dependencies = [('authentication', '0121_extend_ambassador_batch_b')]
    operations = [migrations.RunPython(repair_completed_debits, migrations.RunPython.noop)]
