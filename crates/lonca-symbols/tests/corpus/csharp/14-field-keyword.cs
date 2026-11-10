public class Profile
{
    public string Name
    {
        get;
        set => field = value.Trim();
    } = "";

    public int Length() => Name.Length;
}
