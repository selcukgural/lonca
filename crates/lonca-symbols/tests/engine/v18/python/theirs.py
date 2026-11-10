import os
import sys

import pytest


def charge(amount):
    return amount


def sig(a, b):
    return a + b


def added():
    return sys.argv[0]


class Ledger:
    def __init__(self):
        self.entries = {}

    def add(self, k, v):
        self.entries.setdefault(k, v)

    def total(self):
        return sum(self.entries.values())


@pytest.mark.skip
def test_charges():
    assert charge(2) == 2
