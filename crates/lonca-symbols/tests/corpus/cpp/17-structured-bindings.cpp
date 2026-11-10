#include <map>
#include <string>

int total(const std::map<std::string, int> &counts) {
    int sum = 0;
    for (const auto &[name, count] : counts) {
        sum += count;
    }
    return sum;
}
