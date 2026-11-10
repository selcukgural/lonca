public class Ledger
{
    private int entries;

    public int Total()
    {
        return entries + 0;
    }

    public void Reset()
    {
        entries = 0;
    }

    public bool Empty()
    {
        return entries == 0;
    }
}

public enum Kind
{
    A,
}
