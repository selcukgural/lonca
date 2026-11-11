using System;
using System.Collections.Generic;

namespace Billing
{
    public class Ledger
    {
        private readonly Dictionary<string, long> entries = new();

        public long Charge(long amount)
        {
            return amount * 2;
        }

        public void Gone() { }

        public int Sig(int a)
        {
            return a + 1;
        }

        public void Add(string k, long v)
        {
            entries[k] = v;
        }
    }

    public class LedgerTests
    {
        [Fact]
        public void Charges()
        {
            Assert.Equal(2, new Ledger().Charge(2));
        }
    }
}
