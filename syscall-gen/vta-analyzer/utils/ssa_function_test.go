package utils

import (
	"testing"

	"golang.org/x/tools/go/ssa"
)

func TestFindIndexedFunctionMatchesShapeAndAnyForms(t *testing.T) {
	runtimeName := "(*internal/sync.HashTrieMap[go.shape.*internal/abi.Type,go.shape.interface {}]).LoadOrStore[go.shape.*internal/abi.Type,go.shape.interface {}]"
	ssaName := "(*internal/sync.HashTrieMap[*internal/abi.Type, any]).LoadOrStore[*internal/abi.Type any]"

	fn := new(ssa.Function)
	index := newFunctionIndex()
	indexFunction(index, ssaName, fn)

	if got := findIndexedFunction(index, runtimeName); got != fn {
		t.Fatalf("normalized lookup failed: got %p want %p", got, fn)
	}
}

func TestFindIndexedFunctionFallsBackWhenMethodTypeArgsAreOmitted(t *testing.T) {
	queryName := "(*internal/sync.HashTrieMap[go.shape.*internal/abi.Type,go.shape.interface {}]).LoadOrStore"
	ssaName := "(*internal/sync.HashTrieMap[*internal/abi.Type, any]).LoadOrStore[*internal/abi.Type any]"

	fn := new(ssa.Function)
	index := newFunctionIndex()
	indexFunction(index, ssaName, fn)

	if got := findIndexedFunction(index, queryName); got != fn {
		t.Fatalf("canonical lookup failed: got %p want %p", got, fn)
	}
}
