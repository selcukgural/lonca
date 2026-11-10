using System;

public static class Lambdas
{
    public static Delegate Parser()
    {
        var parse = [Obsolete] int (string s) => int.Parse(s);
        return parse;
    }
}
