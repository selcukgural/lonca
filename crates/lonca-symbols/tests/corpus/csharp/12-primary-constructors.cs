public class Counter(int start)
{
    private int _value = start;
    public int Next() => ++_value;
}
