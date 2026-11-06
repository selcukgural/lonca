import os


def charge(amount):
    return amount


def gone():
    pass


def sig(a):
    return a + 1


class Ledger:
    def __init__(self):
        self.entries = {}

    def add(self, k, v):
        self.entries[k] = v

    def total(self):
        return sum(self.entries.values())


def test_charges():
    assert charge(2) == 2
