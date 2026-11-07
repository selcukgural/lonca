package ledger

type Ledger struct {
	entries int
}

func (l Ledger) Total() int {
	return l.entries
}

func (l *Ledger) Reset() {
	l.entries = 0
}
