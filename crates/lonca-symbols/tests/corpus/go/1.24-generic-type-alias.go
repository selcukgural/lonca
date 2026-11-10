package app

type Set[T comparable] = map[T]struct{}

func Has[T comparable](s Set[T], x T) bool {
	_, ok := s[x]
	return ok
}
