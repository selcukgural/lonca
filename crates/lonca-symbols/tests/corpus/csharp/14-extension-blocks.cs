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
