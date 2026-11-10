int half(int x)
    pre(x % 2 == 0)
    post(r : r * 2 == x)
{
    contract_assert(x >= 0);
    return x / 2;
}
