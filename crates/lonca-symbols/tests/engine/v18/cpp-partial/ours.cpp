struct Counter {
    int value = 0;

    int get(this const Counter& self) {
        return self.value;
    }

    int twice() const {
        return value + value;
    }
};

int total(const Counter& c) {
    return c.value;
}
