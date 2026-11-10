struct Handle {
    Handle(const Handle &) = delete("handles are not copied");
    int id() const {
        return 1;
    }
};
