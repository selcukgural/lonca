_Static_assert(sizeof(int) >= 2, "int is too small");

struct header {
    _Alignas(8) char tag;
    int length;
};

int header_size(void) {
    return (int)_Alignof(struct header);
}
