using System;

public static class Totals
{
    public static int Sum(params ReadOnlySpan<int> xs)
    {
        var total = 0;
        foreach (var x in xs) total += x;
        return total;
    }
}
