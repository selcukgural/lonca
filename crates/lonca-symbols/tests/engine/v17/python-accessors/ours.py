class Tank:
    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, v):
        self._level = v

    @level.deleter
    def level(self):
        del self._level

    def drain(self):
        self._level = 0
