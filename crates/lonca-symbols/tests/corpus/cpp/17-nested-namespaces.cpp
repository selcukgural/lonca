namespace app::billing {
inline int rate = 18;

int tax(int amount) {
    return amount * rate / 100;
}
}
