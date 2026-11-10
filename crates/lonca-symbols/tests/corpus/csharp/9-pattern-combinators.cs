public static class Check
{
    public static bool IsLetter(char c) => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z';
    public static bool Present(object? o) => o is not null;
}
