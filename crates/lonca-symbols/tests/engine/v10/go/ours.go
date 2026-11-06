package billing

import (
	"fmt"
)

func Charge(amount int) int {
	return amount * 2
}

func Gone() {}

func Sig(a int) int {
	return a + 1
}

type Ledger struct {
	entries map[string]int
}

func (l *Ledger) Add(k string, v int) {
	l.entries[k] = v
}

func TestCharges(t *testing.T) {
	if Charge(2) != 2 {
		t.Fatal(fmt.Sprint("bad"))
	}
}
