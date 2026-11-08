"""Savings statement: a PDF a saver can hand to a lender or landlord as
evidence of their saving record on MyFund.

Each statement is stored as a SavingsStatement with a code printed on the PDF
(and as a QR code), so whoever receives it can check the figures at
www.myfundmobile.com/verify/<code> instead of trusting a PDF that could have
been edited.

Figures are deliberately conservative - a credit document should never
overstate:
  * Money in   = QuickSave / AutoSave / QuickInvest / AutoInvest deposits
                 from a bank, card or transfer. Moves between the saver's own
                 wallet, savings and investment are left out.
  * Withdrawn  = money sent out to a bank account.
  * Returns    = quarterly dividends, less withholding tax.
"""
import datetime
import io
from decimal import Decimal
from pathlib import Path

from django.db.models import Q
from django.utils import timezone

from .models import TopSaverHistory, Transaction
from .statement_models import SavingsStatement

ALLOWED_MONTHS = (3, 6, 12)
VERIFY_BASE = "https://www.myfundmobile.com/verify"
MAX_ROWS = 400
LOGO = Path(__file__).parent / "templates" / "MyFund.png"

# The WealthMap scale as the app computes it (MyFundMobileApp/screens/menu/
# useWealthStage.js): the highest stage whose rule the balances meet. Names
# match the app, except stages 1-2: "Debt"/"No Debt" are self-reflection
# prompts in the app, and printing them on a document for a lender would
# claim something about the saver's debts that MyFund doesn't know.
WEALTH_STAGES = [
    (1, "Starter", "No savings or investments on MyFund yet",
     lambda s, i, w: True),
    (2, "Saver", "Has started saving on MyFund",
     lambda s, i, w: s > 0),
    (3, "Surplus", "Investing, or savings of NGN 100,000+",
     lambda s, i, w: i > 0 or s >= 100_000),
    (4, "Savings", "Savings + investments over NGN 300,000",
     lambda s, i, w: s + i > 300_000),
    (5, "Millions", "Savings + investments of NGN 1,000,000+",
     lambda s, i, w: s + i >= 1_000_000),
    (6, "Assets", "Savings + investments of NGN 2,000,000+",
     lambda s, i, w: s + i >= 2_000_000),
    (7, "Passive Income", "NGN 1M+ saved and invested, NGN 100,000+ in returns wallet",
     lambda s, i, w: s + i >= 1_000_000 and w >= 100_000),
    (8, "Financially Free", "NGN 1M+ saved and invested, NGN 500,000+ in returns wallet",
     lambda s, i, w: s + i >= 1_000_000 and w >= 500_000),
    (9, "Legacy Wealth", "NGN 1M+ saved and invested, NGN 1,000,000+ in returns wallet",
     lambda s, i, w: s + i >= 1_000_000 and w >= 1_000_000),
]

DEPOSIT_PREFIXES = ("QuickSave", "AutoSave", "QuickInvest", "AutoInvest")
OWN_ACCOUNTS = {"WALLET", "SAVINGS", "INVESTMENT"}
INTERNAL_DEBIT = Q(description__regex=r"^(Wallet|Savings|Investment) > (Savings|Investment|Wallet)") | \
    Q(description__startswith="Target Savings Initial")


def wealth_stage(savings, investment, wallet):
    s, i, w = (float(x or 0) for x in (savings, investment, wallet))
    for number, name, basis, rule in reversed(WEALTH_STAGES):
        if rule(s, i, w):
            return {"stage": number, "name": name, "basis": basis}


def _month_start(d, back):
    y, m = d.year, d.month - back
    while m <= 0:
        m, y = m + 12, y - 1
    return datetime.date(y, m, 1)


def _is_deposit(tx):
    return (tx.transaction_type == "credit" and tx.description.startswith(DEPOSIT_PREFIXES)
            and "(Abandoned)" not in tx.description and (tx.source or "") not in OWN_ACCOUNTS)


def _is_bank_withdrawal(tx):
    return tx.transaction_type == "debit" and ("> Bank" in tx.description or tx.description.startswith("Withdrawal"))


def _internal_credit_ids(txs):
    """Credits that are the second half of an own-account move (Wallet >
    Savings etc.): paired by reference (<base>-D / <base>-C), or for older
    rows by the same amount within two minutes."""
    debits = [t for t in txs if t.transaction_type == "debit" and t.is_internal]
    refs = {t.transaction_id[:-2] for t in debits if str(t.transaction_id).endswith("-D")}
    used, internal = set(), set()
    for c in txs:
        if c.transaction_type != "credit":
            continue
        tid = str(c.transaction_id)
        if tid.endswith("-C") and tid[:-2] in refs:
            internal.add(c.pk)
            continue
        for d in debits:
            if d.pk not in used and d.amount == c.amount and abs((d.date - c.date).total_seconds()) <= 120:
                used.add(d.pk)
                internal.add(c.pk)
                break
    return internal


def _tenure(joined, today):
    total = (today.year - joined.year) * 12 + today.month - joined.month - (today.day < joined.day)
    years, months = divmod(max(total, 0), 12)
    parts = [f"{n} {unit}{'' if n == 1 else 's'}" for n, unit in ((years, "year"), (months, "month")) if n]
    return " and ".join(parts) or "less than a month", max(total, 0)


def _money(value):
    return f"NGN {Decimal(str(value or 0)):,.0f}"


# Saving discipline: a plain rating a lender can read at a glance, built
# only from rules printed on the statement itself.
DISCIPLINE_RULES = [
    ("Strong", "grew savings in 3 of every 4 months, kept at least half of what was deposited, "
               "6+ months on MyFund"),
    ("Good", "grew savings in at least half the months and kept at least a quarter of deposits"),
    ("Building", "has started saving but not yet consistently"),
    ("Not yet rated", "no saving activity in this period"),
]


def discipline_level(net_saving_months, months, money_in, withdrawn, tenure_months):
    share = net_saving_months / months if months else 0
    kept = (1 - withdrawn / money_in) if money_in > 0 else 0
    if share >= 0.75 and kept >= 0.5 and tenure_months >= 6:
        level = 0
    elif share >= 0.5 and kept >= 0.25:
        level = 1
    elif share > 0 or money_in > 0:
        level = 2
    else:
        level = 3
    name, rule = DISCIPLINE_RULES[level]
    return {"level": name, "rule": rule, "kept_pct": max(0, round(kept * 100)) if money_in > 0 else None}


def build_statement(user, months, now=None):
    """Everything the statement shows, as plain JSON-able data."""
    from .active_saver_views import saving_stats, saving_summaries

    now = timezone.localtime(now or timezone.now())
    today = now.date()
    start = _month_start(today, months - 1)
    period_qs = Transaction.objects.filter(user=user, status="confirmed", date__date__gte=start)
    txs = list(period_qs.order_by("date"))
    internal_debit_ids = set(period_qs.filter(INTERNAL_DEBIT).values_list("pk", flat=True))
    for t in txs:
        t.is_internal = t.pk in internal_debit_ids
    internal_credits = _internal_credit_ids(txs)

    month_keys = [_month_start(today, back) for back in range(months - 1, -1, -1)]
    monthly = {d.strftime("%Y-%m"): {"label": d.strftime("%b %Y"), "money_in": Decimal(0),
                                    "withdrawn": Decimal(0), "returns": Decimal(0)} for d in month_keys}
    rows = []
    for t in txs:
        key = timezone.localtime(t.date).strftime("%Y-%m")
        bucket = monthly.get(key)
        if bucket is not None:
            if _is_deposit(t) and t.pk not in internal_credits:
                bucket["money_in"] += t.amount
            elif _is_bank_withdrawal(t):
                bucket["withdrawn"] += t.amount
            elif t.description.startswith("Dividends") and t.transaction_type == "credit":
                bucket["returns"] += t.amount
            elif t.description.startswith("WHT") and t.transaction_type == "debit":
                bucket["returns"] -= t.amount
        rows.append({"date": timezone.localtime(t.date).strftime("%d %b %Y"), "description": t.description[:60],
                     "type": t.transaction_type, "amount": str(t.amount)})

    total_in = sum((m["money_in"] for m in monthly.values()), Decimal(0))
    total_out = sum((m["withdrawn"] for m in monthly.values()), Decimal(0))
    total_returns = sum((m["returns"] for m in monthly.values()), Decimal(0))
    months_with_deposits = sum(1 for m in monthly.values() if m["money_in"] > 0)

    period_idx = {(d.month, d.year) for d in month_keys}
    net_saving_months = sum(1 for m, y in TopSaverHistory.objects.filter(user=user).values_list("month", "year")
                            if (m, y) in period_idx)
    stats = saving_stats(user, now)
    streak = saving_summaries([user.pk], now)[user.pk]["streak_months"]

    summaries = saving_summaries([user.pk], now)[user.pk]
    top_saver_times = summaries["top_saver_times"]
    returns_all = Transaction.objects.filter(user=user, status="confirmed")
    lifetime_returns = (sum((t for t in returns_all.filter(transaction_type="credit", description__startswith="Dividends")
                             .values_list("amount", flat=True)), Decimal(0))
                        - sum((t for t in returns_all.filter(transaction_type="debit", description__startswith="WHT")
                               .values_list("amount", flat=True)), Decimal(0)))
    tenure_text, tenure_months = _tenure(timezone.localtime(user.date_joined).date(), today)
    discipline = discipline_level(net_saving_months, months, total_in, total_out, tenure_months)

    savings, investment, wallet = (user.savings or Decimal(0)), (user.investment or Decimal(0)), (user.wallet or Decimal(0))
    first = ((user.first_name or "").strip().split(" ") or [""])[0].title() or "This saver"
    held = savings + investment + wallet
    headline = f"In {tenure_text}, {first} has built {_money(held)} with MyFund"
    headline += f" and earned {_money(lifetime_returns)} in dividends." if lifetime_returns > 0 else "."
    highlights = [headline]
    if top_saver_times:
        highlights.append(f"Top Saver {top_saver_times} time{'s' if top_saver_times != 1 else ''} "
                          "(finished in a monthly Top 3 of MyFund savers).")
    highlights.append(f"Grew their savings in {net_saving_months} of the last {months} months"
                      + (f", and is on a {streak}-month saving streak." if streak >= 2 else "."))
    if discipline["kept_pct"] is not None:
        highlights.append(f"Kept {discipline['kept_pct']}% of the money they deposited in this period.")
    if user.autosave_enabled or user.autoinvest_enabled:
        highlights.append("Saves automatically with " + " and ".join(
            n for n, on in (("AutoSave", user.autosave_enabled), ("AutoInvest", user.autoinvest_enabled)) if on) + ".")
    name = " ".join(p for p in [(user.first_name or "").strip(), (user.last_name or "").strip()] if p) or user.email
    return {
        "name": name.title(),
        "email": user.email,
        "phone": user.phone_number or "",
        "member_since": timezone.localtime(user.date_joined).strftime("%d %b %Y"),
        "kyc_verified": user.kyc_status == "approved",
        "issued_at": now.strftime("%d %b %Y, %H:%M"),
        "period_start": start.isoformat(),
        "period_end": today.isoformat(),
        "period_label": f"{start.strftime('%d %b %Y')} – {today.strftime('%d %b %Y')}",
        "months": months,
        "balances": {"savings": str(savings), "investment": str(investment), "wallet": str(wallet),
                     "total": str(savings + investment + wallet)},
        "totals": {"money_in": str(total_in), "withdrawn": str(total_out), "returns": str(total_returns),
                   "net_saved": str(total_in - total_out)},
        "record": {"months_with_deposits": months_with_deposits, "net_saving_months": net_saving_months,
                   "current_streak": streak, "longest_streak": stats["longest_streak"],
                   "autosave": bool(user.autosave_enabled), "autoinvest": bool(user.autoinvest_enabled)},
        "stage": wealth_stage(savings, investment, wallet),
        "tenure": tenure_text,
        "top_saver_times": top_saver_times,
        "lifetime_returns": str(lifetime_returns),
        "discipline": discipline,
        "highlights": highlights,
        "monthly": [{**v, "money_in": str(v["money_in"]), "withdrawn": str(v["withdrawn"]),
                     "returns": str(v["returns"])} for v in monthly.values()],
        "transactions": rows[-MAX_ROWS:][::-1],
        "transactions_truncated": len(rows) > MAX_ROWS,
    }


def issue_statement(user, months):
    data = build_statement(user, months)
    summary = {k: v for k, v in data.items() if k not in ("transactions", "monthly", "email", "phone")}
    statement = SavingsStatement.objects.create(
        user=user, months=months, summary=summary,
        period_start=data["period_start"], period_end=data["period_end"])
    data["code"] = statement.code
    data["verify_url"] = f"{VERIFY_BASE}/{statement.code}"
    return statement, data


def public_summary(statement):
    """What the verify page shows: the issued figures, no contact details or
    transaction lines."""
    s = statement.summary
    return {"code": statement.code, "valid": True, "name": s.get("name"), "issued_at": s.get("issued_at"),
            "period_label": s.get("period_label"), "months": statement.months,
            "member_since": s.get("member_since"), "kyc_verified": s.get("kyc_verified"),
            "balances": s.get("balances"), "totals": s.get("totals"), "record": s.get("record"),
            "stage": s.get("stage"), "discipline": s.get("discipline"), "highlights": s.get("highlights"),
            "tenure": s.get("tenure"), "top_saver_times": s.get("top_saver_times"), "days_old": (timezone.now() - statement.created_at).days}


# ─────────────────────────── PDF ───────────────────────────

def _naira(value):
    v = Decimal(str(value or 0))
    return f"{'-' if v < 0 else ''}NGN {abs(v):,.2f}"


def render_pdf(data):
    import qrcode
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (Image, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    purple, light, grey = colors.HexColor("#351265"), colors.HexColor("#F3EEFB"), colors.HexColor("#6B7280")
    base = ParagraphStyle("b", fontName="Helvetica", fontSize=8.5, leading=11)
    small = ParagraphStyle("s", parent=base, fontSize=7, leading=9, textColor=grey)
    h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11, leading=14,
                        textColor=purple, spaceBefore=8, spaceAfter=4)
    title = ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=16, leading=19, textColor=purple)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm,
                            bottomMargin=16 * mm, title=f"MyFund Savings Statement {data['code']}",
                            author="MyFund")
    W = A4[0] - 32 * mm
    qr_buf = io.BytesIO()
    qrcode.make(data["verify_url"], box_size=6, border=1).save(qr_buf, format="PNG")
    qr_buf.seek(0)

    def grid(rows, widths, header=True, align_right_from=1):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [("FONT", (0, 0), (-1, -1), "Helvetica", 8), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                 ("ALIGN", (align_right_from, 0), (-1, -1), "RIGHT"),
                 ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#E5E7EB")),
                 ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), purple), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                      ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8)]
        t.setStyle(TableStyle(style))
        return t

    story = []
    head = Table([[Image(str(LOGO), width=46 * mm, height=18 * mm),
                   [Paragraph("Savings Statement", title),
                    Paragraph(f"Statement no. <b>{data['code']}</b><br/>Issued {data['issued_at']} (WAT)<br/>"
                              f"Period: {data['period_label']}", base)]]],
                 colWidths=[60 * mm, W - 60 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT")]))
    story += [head, Spacer(1, 4)]

    kyc = "Verified (KYC approved)" if data["kyc_verified"] else "Not yet verified"
    holder = Table([
        [Paragraph(f"<b>{data['name']}</b><br/>{data['email']}<br/>{data['phone']}", base),
         Paragraph(f"Member since <b>{data['member_since']}</b><br/>Identity: <b>{kyc}</b>", base)]],
        colWidths=[W / 2, W / 2])
    holder.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), light), ("BOX", (0, 0), (-1, -1), 0.5, purple),
                                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story.append(holder)

    # The story first: what a lender or landlord actually wants to know.
    disc = data["discipline"]
    lead = ParagraphStyle("lead", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=16, textColor=purple)
    bullet = ParagraphStyle("bl", parent=base, fontSize=9.5, leading=13, leftIndent=10, bulletIndent=0)
    badge = ParagraphStyle("bd", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=16,
                           textColor=colors.white, alignment=1)
    story_cells = [Paragraph(data["highlights"][0], lead), Spacer(1, 4)] + [
        Paragraph(h, bullet, bulletText="\u2022") for h in data["highlights"][1:]]
    disc_cell = [Paragraph("SAVING DISCIPLINE", ParagraphStyle("dl", parent=small, textColor=colors.white,
                                                               alignment=1)),
                 Paragraph(disc["level"], badge),
                 Paragraph(f"Level {data['stage']['stage']}/9 on the MyFund WealthMap",
                           ParagraphStyle("dw", parent=small, textColor=colors.white, alignment=1))]
    hero = Table([[story_cells, disc_cell]], colWidths=[W - 42 * mm, 42 * mm])
    hero.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (1, 0), (1, 0), purple),
                              ("BOX", (0, 0), (-1, -1), 0.8, purple), ("TOPPADDING", (0, 0), (-1, -1), 8),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [Spacer(1, 8), hero]

    b, t, r = data["balances"], data["totals"], data["record"]
    story.append(Paragraph("Summary", h2))
    summary = [
        ["Balances on the issue date", "", f"Activity, last {data['months']} months", ""],
        ["Savings", _naira(b["savings"]), "Money in (bank, card, AutoSave)", _naira(t["money_in"])],
        ["Investments", _naira(b["investment"]), "Withdrawn to bank", _naira(t["withdrawn"])],
        ["Wallet (returns)", _naira(b["wallet"]), "Net saved", _naira(t["net_saved"])],
        ["Total held", _naira(b["total"]), "Returns earned (after tax)", _naira(t["returns"])],
    ]
    st = grid(summary, [W * 0.22, W * 0.24, W * 0.30, W * 0.24])
    st.setStyle(TableStyle([("SPAN", (0, 0), (1, 0)), ("SPAN", (2, 0), (3, 0)), ("ALIGN", (0, 0), (-1, 0), "LEFT"),
                            ("FONT", (0, 4), (1, 4), "Helvetica-Bold", 8)]))
    story.append(st)

    story.append(Paragraph("Saving record", h2))
    yes = lambda v: "On" if v else "Off"
    story.append(grid([
        ["Months with deposits in this period", f"{r['months_with_deposits']} of {data['months']}"],
        ["Months where savings grew (saved more than withdrew)", f"{r['net_saving_months']} of {data['months']}"],
        ["Current saving streak", f"{r['current_streak']} month(s) in a row"],
        ["Longest saving streak on MyFund", f"{r['longest_streak']} month(s)"],
        ["AutoSave / AutoInvest", f"{yes(r['autosave'])} / {yes(r['autoinvest'])}"],
        ["Top Saver (monthly Top 3) finishes", str(data["top_saver_times"])],
    ], [W * 0.7, W * 0.3], header=False))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>How the saving discipline rating works:</b> " + "; ".join(
        f"<b>{n}</b> - {rule}" for n, rule in DISCIPLINE_RULES) + ".", small))

    # WealthMap scale: nine steps, the saver's stage filled in.
    stage = data["stage"]
    story.append(Paragraph("MyFund WealthMap level", h2))
    cells = [[f"{n}" for n, *_ in WEALTH_STAGES], [name for _, name, *_ in WEALTH_STAGES]]
    scale = Table(cells, colWidths=[W / 9] * 9)
    scale_style = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 10),
                   ("FONT", (0, 1), (-1, 1), "Helvetica", 6.5), ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
                   ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E9E3F5")),
                   ("TEXTCOLOR", (0, 0), (-1, -1), grey)]
    for col in range(stage["stage"]):
        scale_style += [("BACKGROUND", (col, 0), (col, 1), colors.HexColor("#B9A6E0")),
                        ("TEXTCOLOR", (col, 0), (col, 1), purple)]
    scale_style += [("BACKGROUND", (stage["stage"] - 1, 0), (stage["stage"] - 1, 1), purple),
                    ("TEXTCOLOR", (stage["stage"] - 1, 0), (stage["stage"] - 1, 1), colors.white)]
    scale.setStyle(TableStyle(scale_style))
    story += [scale, Spacer(1, 3), Paragraph(
        f"<b>Level {stage['stage']} of 9 - {stage['name']}:</b> {stage['basis']}. The level is set only by the "
        "balances held on MyFund; it does not assess income, debts or accounts elsewhere.", base)]

    story.append(Paragraph("Month by month", h2))
    story.append(grid([["Month", "Money in", "Withdrawn to bank", "Returns (after tax)"]] +
                      [[m["label"], _naira(m["money_in"]), _naira(m["withdrawn"]), _naira(m["returns"])]
                       for m in data["monthly"]], [W * 0.25] * 4))

    story.append(Paragraph("Transactions", h2))
    if data["transactions"]:
        rows = [["Date", "Description", "In", "Out"]] + [
            [x["date"], Paragraph(x["description"], base),
             _naira(x["amount"]) if x["type"] == "credit" else "",
             _naira(x["amount"]) if x["type"] == "debit" else ""] for x in data["transactions"]]
        story.append(grid(rows, [W * 0.16, W * 0.52, W * 0.16, W * 0.16], align_right_from=2))
        if data["transactions_truncated"]:
            story.append(Paragraph(f"Showing the latest {MAX_ROWS} transactions in this period.", small))
    else:
        story.append(Paragraph("No transactions in this period.", base))

    verify = Table([[Image(qr_buf, width=24 * mm, height=24 * mm), Paragraph(
        f"<b>Verify this statement</b><br/>Scan the code or visit <b>{data['verify_url']}</b> to confirm the "
        f"figures above match what MyFund issued. Statement no. {data['code']}.<br/><br/>"
        "Money in counts deposits from a bank, card or AutoSave/AutoInvest only; moves between the saver's own "
        "MyFund wallet, savings and investments are not counted. Returns are quarterly dividends less 10% "
        "withholding tax. This statement records activity on MyFund and is not a credit score or a guarantee.",
        small)]], colWidths=[28 * mm, W - 28 * mm])
    verify.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.5, purple),
                                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [Spacer(1, 10), KeepTogether(verify)]

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(grey)
        canvas.drawString(16 * mm, 9 * mm, f"MyFund Savings Statement {data['code']} · {data['name']}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
