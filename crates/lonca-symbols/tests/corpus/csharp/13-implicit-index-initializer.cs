public class Countdown
{
    public int[] Values = new int[3];
}

public static class Countdowns
{
    public static Countdown Make() => new Countdown { Values = { [^1] = 0, [^2] = 1 } };
}
