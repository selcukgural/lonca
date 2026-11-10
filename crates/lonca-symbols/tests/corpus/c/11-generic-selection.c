#define kind(x) _Generic((x), int: "int", double: "double", default: "other")

const char *kind_of_int(void) {
    return kind(1);
}
