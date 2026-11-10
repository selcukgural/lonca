package app

import "iter"

func Evens(limit int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := 0; i < limit; i += 2 {
			if !yield(i) {
				return
			}
		}
	}
}

func Total(limit int) int {
	total := 0
	for x := range Evens(limit) {
		total += x
	}
	return total
}
