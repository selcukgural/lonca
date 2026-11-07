class Client
{
    public void Charge(string card)
    {
        Log(card);
        Pay(card);
    }

    public void Refund(long amount)
    {
        Back(amount);
    }
}
