struct point {
    int x, y;
};

int origin_x(void) {
    struct point p = {};
    return p.x;
}
