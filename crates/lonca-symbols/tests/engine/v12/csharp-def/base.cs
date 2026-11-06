public class Ledger
{
    private int entries;

    public int Total()
    {
        return entries;
    }

    public void Reset()
    {
        entries = 0;
    }
}

public enum Kind
{
    A,
}
