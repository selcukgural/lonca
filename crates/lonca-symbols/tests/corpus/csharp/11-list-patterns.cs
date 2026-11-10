public static class Lists
{
    public static int FirstOrZero(int[] xs) => xs is [var first, .., > 0] ? first : 0;
}
