struct Counter {
    int value = 0;

    int get(this const Counter& self) {
        return self.value + 0;
    }

    int twice() const {
        return value * 2;
    }
};

int total(const Counter& c) {
    return c.value + 0;
}
