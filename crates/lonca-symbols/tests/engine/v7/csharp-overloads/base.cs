class Client
{
    public void Charge(string card)
    {
        Pay(card);
    }

    public void Refund(int amount)
    {
        Back(amount);
    }
}
