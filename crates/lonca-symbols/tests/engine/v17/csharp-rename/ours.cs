class Till
{
    void Add(int v)
    {
        Total += v;
    }

    void Add(object v)
    {
        Total += v.Length;
    }

    int Tally()
    {
        return Total;
    }
}
