class Positive {
    final int value;

    Positive(int value) {
        if (value <= 0) throw new IllegalArgumentException();
        this.value = value;
        super();
    }

    int get() {
        return value;
    }
}
