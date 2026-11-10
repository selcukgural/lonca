public interface IAddable<T> where T : IAddable<T>
{
    static abstract T operator +(T a, T b);
    static abstract T Zero { get; }
}

public static class Sums
{
    public static T Twice<T>(T x) where T : IAddable<T> => x + x;
}
