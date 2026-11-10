package app

type Stack[T any] struct {
	items []T
}

func (s *Stack[T]) Map[U any](f func(T) U) []U {
	var out []U
	for _, item := range s.items {
		out = append(out, f(item))
	}
	return out
}
