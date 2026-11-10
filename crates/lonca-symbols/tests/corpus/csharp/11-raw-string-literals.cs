public static class Texts
{
    public static string Json(string name) => $$"""
        { "name": "{{name}}" }
        """;
}
