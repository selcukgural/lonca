[System.Runtime.CompilerServices.InlineArray(4)]
public struct Buffer4
{
    private int _first;
}

public static class Buffers
{
    public static int First(Buffer4 b) => b[0];
}
