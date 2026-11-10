public class Order
{
    public int Count;
}

public static class Orders
{
    public static void Reset(Order? o)
    {
        o?.Count = 0;
    }
}
