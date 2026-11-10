using System.Collections.Generic;

public static class Numbers
{
    public static List<int> Join(int[] a, int[] b) => [.. a, 0, .. b];
}
