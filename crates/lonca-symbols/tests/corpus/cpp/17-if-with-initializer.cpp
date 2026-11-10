#include <map>

int find(const std::map<int, int> &m, int key) {
    if (auto it = m.find(key); it != m.end()) {
        return it->second;
    }
    return 0;
}
