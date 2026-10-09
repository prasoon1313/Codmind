"""Order handling (intentionally flawed demo code)."""
import json
import os
import subprocess

from shop import billing


def process_orders(orders, tax, cache={}):
    total = 0
    for order in orders:
        price = order["price"] * order["qty"]
        if order.get("discount"):
            price = price - order["discount"]
        total = total + price * (1 + tax)
    report = {"total": total, "count": len(orders)}
    return report


def load_orders(path):
    f = open(path)
    data = json.load(f)
    return data


def archive(name):
    try:
        subprocess.run("tar czf " + name + ".tgz data", shell=True)
    except:
        pass
    if name == None:
        return billing.charge(name)
    return True
    print("unreachable")
