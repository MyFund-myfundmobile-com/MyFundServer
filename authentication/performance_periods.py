"""Shared calendar windows for ambassador and influencer performance."""
from datetime import date
from django.utils import timezone

PERIOD_LABELS = {
    "this_month": "This month",
    "last_month": "Last month",
    "last_3_months": "Last 3 months",
    "last_6_months": "Last 6 months",
    "last_year": "Last year",
    "all_time": "All time",
}


def performance_months(period, earliest, today=None):
    if period not in PERIOD_LABELS:
        raise ValueError("Invalid performance period.")
    today = today or timezone.localdate()
    current = today.year * 12 + today.month - 1
    end = current
    if period == "this_month":
        start = current
    elif period == "last_month":
        start = end = current - 1
    elif period == "last_3_months":
        start = current - 2
    elif period == "last_6_months":
        start = current - 5
    elif period == "last_year":
        start, end = (today.year - 1) * 12, today.year * 12 - 1
    else:
        start = min(earliest.year * 12 + earliest.month - 1, current)
    return [date(index // 12, index % 12 + 1, 1).strftime("%Y-%m")
            for index in range(start, end + 1)]
