struct Counter {
    int value = 0;

    template <typename Self>
    auto &&get(this Self &&self) {
        return self.value;
    }

    int next(this Counter &self) {
        return ++self.value;
    }
};
