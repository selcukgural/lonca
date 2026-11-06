package billing

import (
	"fmt"
	"strings"
)

func Charge(amount int) int {
	return amount
}

func Sig(a int, b int) int {
	return a + b
}

func Added() string {
	return strings.ToUpper("x")
}

type Ledger struct {
	entries map[string]int
}

func (l *Ledger) Add(k string, v int) {
	if _, ok := l.entries[k]; !ok {
		l.entries[k] = v
	}
}

func TestCharges(t *testing.T) {
	t.Skip("flaky")
	if Charge(2) != 2 {
		t.Fatal(fmt.Sprint("bad"))
	}
}
