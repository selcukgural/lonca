using System.Collections.Generic;

public class Registry
{
    private readonly Dictionary<string, List<int>> _items = new();
    public int Count() => _items.Count;
}
