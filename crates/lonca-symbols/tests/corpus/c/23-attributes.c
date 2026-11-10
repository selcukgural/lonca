[[nodiscard]] int open_file(const char *path);

[[deprecated("use open_file")]] int old_open(const char *path) {
    [[maybe_unused]] int unused = 0;
    return open_file(path);
}
