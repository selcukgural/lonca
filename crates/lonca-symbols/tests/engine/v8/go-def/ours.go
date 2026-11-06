package ledger

type Ledger struct {
	entries int
}

func (l Ledger) Total() int {
	return l.entries + 0
}

func (l *Ledger) Reset() {
	l.entries = 0
}

func (l Ledger) Empty() bool {
	return l.entries == 0
}
