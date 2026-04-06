from authentication.models import Transaction


def run():
    updated = 0

    for txn in Transaction.objects.filter(credited_to__isnull=True):
        desc = (txn.description or "").strip().lower()
        credited_to = None

        # Savings
        if (
            desc.startswith("quicksave")
            or desc.startswith("autosave")
            or "wallet > savings" in desc
            or desc == "savings for investment purposes cancelled"
        ):
            credited_to = "SAVINGS"

        # Investment
        elif (
            desc.startswith("quickinvest")
            or desc.startswith("autoinvest")
            or "wallet > investment" in desc
            or desc == "personal project"
        ):
            credited_to = "INVESTMENT"

        # Wallet
        elif (
            desc.startswith("dividends:")
            or desc.startswith("refund for incomplete target")
            or desc == "staff allowance credit"
            or desc == "scheduled withdrawal"
        ):
            credited_to = "WALLET"

        if credited_to:
            txn.credited_to = credited_to
            txn.save(update_fields=["credited_to"])

            updated += 1
            print(
                f"UPDATED -> {txn.user.email} | ₦{txn.amount} | {txn.description} | {credited_to}"
            )

    print(f"\nDone. Updated {updated} transactions.")
