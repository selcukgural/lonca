public readonly record struct Money(decimal Amount, string Currency)
{
    public Money Add(Money other) => this with { Amount = Amount + other.Amount };
}
