enum flag : unsigned char { off, on };

int is_on(enum flag f) {
    return f == on;
}
