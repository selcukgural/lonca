struct Grid {
    int cells[4][4];

    int &operator[](int row, int column) {
        return cells[row][column];
    }
};

int corner(Grid &g) {
    return g[3, 3];
}
