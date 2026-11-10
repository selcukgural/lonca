public class Meter
{
    public int Value;
    public void operator +=(int by) { Value += by; }
    public int Read() => Value;
}
