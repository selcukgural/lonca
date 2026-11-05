@frozen
class Ledger(Base):
    limit = 2

    def total(self):
        return 1

    def reset(self):
        return 3
