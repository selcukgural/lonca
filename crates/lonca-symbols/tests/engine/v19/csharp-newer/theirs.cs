static class E
{
    public static int One() => 1;

    public static int Two() => 2;

    extension(string s)
    {
        public int Size => s.Length;
    }
}
