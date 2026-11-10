public class Account
{
    public required string Owner { get; init; }
    public string Describe() => Owner;
}
