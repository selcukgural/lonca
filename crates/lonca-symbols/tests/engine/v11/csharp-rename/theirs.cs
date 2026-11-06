class Till
{
    void Add(int v)
    {
        Total += v + 1;
    }

    void Add(string v)
    {
        Total += v.Length;
    }

    int Sum()
    {
        return Total;
    }
}
