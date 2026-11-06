class Tank:
    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, v):
        self._level = max(v, 0)

    def drain(self):
        self._level = 0
