public partial class Settings
{
    public partial string Name { get; set; }
}

public partial class Settings
{
    private string _name = "";
    public partial string Name { get => _name; set => _name = value; }
}
