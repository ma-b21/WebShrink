package builder

import (
	"testing"

	"github.com/bits-and-blooms/bitset"
)

func TestBuildDAGRetainsInvokeEdgesForPropagation(t *testing.T) {
	const syscallID = 99

	caller := &UnifiedNode{
		Key:           "caller",
		HasSSA:        true,
		Pos:           "/tmp/caller.go:10:1",
		SyscallBitSet: bitset.New(512),
	}
	callee := &UnifiedNode{
		Key:           "callee",
		HasSSA:        true,
		Pos:           "/tmp/callee.go:20:1",
		SyscallBitSet: bitset.New(512),
	}
	callee.SyscallBitSet.Set(syscallID)

	linkTestNodes(caller, callee, "vta", &VTAEdgeInfo{
		HasSite:  true,
		IsInvoke: true,
	})

	dag := BuildDAG(&UnifiedCallGraph{
		Nodes: map[string]*UnifiedNode{
			caller.Key: caller,
			callee.Key: callee,
		},
		Syscalls: map[string][]int{},
	})
	dag.ComputeSCC()
	dag.BuildSCCGraph()
	dag.PropagateSyscalls()

	node := dag.Nodes[caller.Key]
	if node == nil {
		t.Fatalf("caller node missing from DAG")
	}
	if !node.SyscallBitSet.Test(syscallID) {
		t.Fatalf("expected invoke edge to propagate syscall %d into caller", syscallID)
	}
}

func TestBuildDAGStillSkipsDynamicFuncEdges(t *testing.T) {
	const syscallID = 101

	caller := &UnifiedNode{
		Key:           "caller",
		HasSSA:        true,
		Pos:           "/tmp/caller.go:10:1",
		SyscallBitSet: bitset.New(512),
	}
	callee := &UnifiedNode{
		Key:           "callee",
		HasSSA:        true,
		Pos:           "/tmp/callee.go:20:1",
		SyscallBitSet: bitset.New(512),
	}
	callee.SyscallBitSet.Set(syscallID)

	linkTestNodes(caller, callee, "vta", &VTAEdgeInfo{
		HasSite:       true,
		IsDynamicFunc: true,
	})

	dag := BuildDAG(&UnifiedCallGraph{
		Nodes: map[string]*UnifiedNode{
			caller.Key: caller,
			callee.Key: callee,
		},
		Syscalls: map[string][]int{},
	})
	dag.ComputeSCC()
	dag.BuildSCCGraph()
	dag.PropagateSyscalls()

	node := dag.Nodes[caller.Key]
	if node == nil {
		t.Fatalf("caller node missing from DAG")
	}
	if node.SyscallBitSet.Test(syscallID) {
		t.Fatalf("did not expect dynamic-func edge to propagate syscall %d into caller", syscallID)
	}
}
