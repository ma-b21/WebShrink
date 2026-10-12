package types

type Set[T comparable] struct {
	m map[T]struct{}
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{m: make(map[T]struct{})}
}

func (s *Set[T]) Add(v T) {
	s.m[v] = struct{}{}
}

func (s *Set[T]) Has(v T) bool {
	_, ok := s.m[v]
	return ok
}

func (s *Set[T]) Delete(v T) {
	delete(s.m, v)
}

func (s *Set[T]) Items() map[T]struct{} {
	return s.m
}

func (s *Set[T]) ToSlice() []T {
	res := make([]T, 0, len(s.m))
	for k := range s.m {
		res = append(res, k)
	}
	return res
}

func NewSetFromSlice[T comparable](items []T) *Set[T] {
	s := NewSet[T]()
	for _, v := range items {
		s.Add(v)
	}
	return s
}


type AsmFunction struct {
	FuncName    string
	Callees     []string
	SyscallLine []int
	Syscalls    []string
}

func (fn *AsmFunction) Equals(otherFn *AsmFunction) bool {
	return fn.FuncName == otherFn.FuncName
}