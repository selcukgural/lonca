class Client
{
    public void Charge(int amount, int fee)
    {
        Pay(amount + fee);
    }

    public void Charge(string card)
    {
        Pay(card);
    }

    public void Refund(int amount)
    {
        Back(amount);
    }
}
