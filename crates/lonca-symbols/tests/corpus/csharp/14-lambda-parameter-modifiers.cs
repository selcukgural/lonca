public static class Parsers
{
    private delegate bool TryParse(string text, out int result);

    public static bool Run(string s)
    {
        TryParse parse = (text, out result) => int.TryParse(text, out result);
        return parse(s, out _);
    }
}
