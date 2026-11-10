file class Helper
{
    public static int Twice(int x) => x * 2;
}

public class Doubler
{
    public int Run(int x) => Helper.Twice(x);
}
