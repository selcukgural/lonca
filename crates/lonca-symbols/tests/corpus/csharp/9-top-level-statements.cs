using System;

Console.WriteLine(Greeter.Hello("lonca"));

static class Greeter
{
    public static string Hello(string name) => "hello " + name;
}
