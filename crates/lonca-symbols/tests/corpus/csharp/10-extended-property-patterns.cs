public record Address(string City);
public record Customer(Address Address);

public static class Rules
{
    public static bool Local(Customer c) => c is { Address.City: "Ankara" };
}
