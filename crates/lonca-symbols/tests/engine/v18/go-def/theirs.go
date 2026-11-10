package ledger

type Ledger struct {
	entries int
	closed  bool
}

func (l Ledger) Total() int {
	return l.entries
}

func (l *Ledger) Reset() {
	l.entries = 1
}
