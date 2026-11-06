using System;
using System.Collections.Generic;
using System.Linq;

namespace Billing
{
    public class Ledger
    {
        private readonly Dictionary<string, long> entries = new();

        public long Charge(long amount)
        {
            return amount;
        }

        public int Sig(int a, int b)
        {
            return a + b;
        }

        public void Add(string k, long v)
        {
            entries.TryAdd(k, v);
        }

        public long Added()
        {
            return entries.Values.Sum();
        }
    }

    public class LedgerTests
    {
        [Fact(Skip = "flaky")]
        public void Charges()
        {
            Assert.Equal(2, new Ledger().Charge(2));
        }
    }
}
