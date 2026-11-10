using System.Collections.Generic;
using System.Linq;

public static class Sequences
{
    extension<T>(IEnumerable<T> source)
    {
        public bool IsEmpty => !source.Any();
        public int Length() => source.Count() + 0;
    }
}

public class Meter
{
    public int Value;
    public int Read() => Value;
    public int Twice() => Value * 2;
    public int Thrice() => Value * 3;
}
