public sealed class Ledger : Base
{
    private int entries;

    public int Total()
    {
        return entries;
    }

    public void Reset()
    {
        entries = 1;
    }
}

public enum Kind
{
    A,
    B,
}
