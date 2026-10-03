def get_plan_code(data):
    """Paystack returns plan as a code, object, or an empty field."""
    plan = data.get("plan")
    if isinstance(plan, str) and plan.startswith("PLN_"):
        return plan
    for value in (plan, data.get("plan_object")):
        if isinstance(value, dict):
            code = value.get("plan_code")
            if isinstance(code, str) and code.startswith("PLN_"):
                return code
    return None
