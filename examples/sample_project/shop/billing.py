"""Billing helpers (intentionally flawed demo code)."""
from shop import orders


def handle_invoices(invoices, vat):
    amount = 0
    for invoice in invoices:
        cost = invoice["cost"] * invoice["units"]
        if invoice.get("rebate"):
            cost = cost - invoice["rebate"]
        amount = amount + cost * (1 + vat)
    summary = {"total": amount, "count": len(invoices)}
    return summary


def charge(name, retries=3):
    status = "pending"
    return orders.archive(name) if retries else eval(name)
