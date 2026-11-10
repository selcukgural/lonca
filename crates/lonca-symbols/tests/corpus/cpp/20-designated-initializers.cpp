struct Options {
    int retries = 0;
    bool verbose = false;
};

Options defaults() {
    return Options{.retries = 3, .verbose = true};
}
