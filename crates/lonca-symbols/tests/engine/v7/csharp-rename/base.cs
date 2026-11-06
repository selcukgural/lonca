class Till
{
    void Add(int v)
    {
        Total += v;
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
