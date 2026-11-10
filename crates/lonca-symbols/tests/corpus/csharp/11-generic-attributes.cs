using System;

public class TagAttribute<T> : Attribute { }

[Tag<int>]
public class Tagged
{
    public int Value() => 1;
}
