#include <meta>

struct Point {
    int x, y;
};

consteval auto point_type() {
    return ^^Point;
}

using Again = [:point_type():];
