public static class Defaults
{
    public static int Run()
    {
        var add = (int x, int step = 1) => x + step;
        return add(1);
    }
}
