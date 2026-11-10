package app

func Squares(n int) []int {
	var out []int
	for i := range n {
		out = append(out, i*i)
	}
	return out
}
