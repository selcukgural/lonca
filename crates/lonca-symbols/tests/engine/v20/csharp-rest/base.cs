public static class Sequences
{
    extension<T>(IEnumerable<T> source)
        where T : notnull
    {
        public int Length() => source.Count();
    }
}

public class Meter
{
    public int Value;
    public int Read() => Value;
    public int Twice() => Value * 2;
}
