struct Twice {
    static int operator()(int x) {
        return x * 2;
    }
};

int four() {
    return Twice{}(2);
}
