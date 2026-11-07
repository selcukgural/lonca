import os


class Ledger:
    def total(self, fee):
        s = 0
        for e in self.entries:
            s += e
        fee = max(fee, 0)
        return s + fee

    def count(self):
        return len(self.entries)


def charge(amount):
    a = amount
    b = 1
    return a + b
