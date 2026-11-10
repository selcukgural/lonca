using System.Collections.Generic;
using System.Linq;

public static class Sequences
{
    extension<T>(IEnumerable<T> source)
    {
        public bool IsEmpty => !source.Any();
        public int Length() => source.Count();
    }
}

public class Meter
{
    public int Value;
    public int Read() => Value + 1;
    public int Twice() => Value * 2;
}
