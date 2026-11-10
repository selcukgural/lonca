#include <compare>

struct Version {
    int major, minor;
    auto operator<=>(const Version &) const = default;
};

bool newer(Version a, Version b) {
    return (a <=> b) > 0;
}
