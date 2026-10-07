from django.db import migrations

BODIES = {
    "founder": "Today, vote for our founder, Dr. Tee, as **Founder of the Year**. It's free, once a day.",
    "realestate": "Today, vote MyFund for **Real Estate & Urban Development**. It's free, once a day.",
    "fintech": "Today, vote MyFund for **Fintech & Financial Innovation**. It's free, once a day.",
}


def add_banner_body(apps, schema_editor):
    # Banner copy per category, kept in the categories JSON so it can be
    # edited in the admin without an app update (**text** = bold).
    Campaign = apps.get_model("authentication", "FoyaCampaign")
    for campaign in Campaign.objects.all():
        campaign.categories = [
            {**c, "banner_body": c.get("banner_body") or BODIES.get(c.get("key"), "")}
            for c in campaign.categories or []
        ]
        campaign.save(update_fields=["categories"])


class Migration(migrations.Migration):
    dependencies = [("authentication", "0116_foya_positions")]
    operations = [migrations.RunPython(add_banner_body, migrations.RunPython.noop)]
