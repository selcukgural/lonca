consteval int square(int x) {
    return x * x;
}

constinit int area = square(4);

int get_area() {
    return area;
}
