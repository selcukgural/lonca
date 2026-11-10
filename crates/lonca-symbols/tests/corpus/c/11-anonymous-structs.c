struct value {
    int kind;
    union {
        int number;
        double real;
    };
};

int number_of(struct value v) {
    return v.number;
}
