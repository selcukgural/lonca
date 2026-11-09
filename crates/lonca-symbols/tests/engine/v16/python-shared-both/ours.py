import os


class Ledger:
    def total(self, fee):
        s = 0.0
        for e in self.entries:
            s += e
        fee = fee
        return s + fee

    def count(self):
        return len(self.entries)


def charge(amount):
    a = int(amount)
    b = 0
    return a + b
