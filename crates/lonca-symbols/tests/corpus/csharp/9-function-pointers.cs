public static unsafe class Calls
{
    public static int Apply(delegate*<int, int> f, int x) => f(x);
}
