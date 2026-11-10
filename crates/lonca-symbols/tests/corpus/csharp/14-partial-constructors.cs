public partial class Widget
{
    public partial Widget(int size);
}

public partial class Widget
{
    private readonly int _size;
    public partial Widget(int size) { _size = size; }
    public int Size() => _size;
}
