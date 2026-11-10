"""Summarise a ledger CSV export."""
import csv
import sys
from collections import defaultdict


def summarise(path):
    totals = defaultdict(float)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            totals[row["account"]] += float(row["amount"])
    return dict(totals)


if __name__ == "__main__":
    for account, total in sorted(summarise(sys.argv[1]).items()):
        print(f"{account:<12} {total:>10.2f}")
