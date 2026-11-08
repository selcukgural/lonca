package till

func (t *Till) Add(v int) {
	t.total += v
}

func (t *Till) Sum() int {
	return t.total * 2
}
