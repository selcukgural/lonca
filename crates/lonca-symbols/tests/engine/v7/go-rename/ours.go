package till

func (t *Till) Deposit(v int) {
	t.total += v
}

func (t *Till) Sum() int {
	return t.total
}
