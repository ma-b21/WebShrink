package builder

import (
	"testing"

	"github.com/bits-and-blooms/bitset"
)

func TestNormalizedFuncNameMatchesShapeAndAnyForms(t *testing.T) {
	runtimeName := "(*internal/sync.HashTrieMap[go.shape.*internal/abi.Type,go.shape.interface {}]).LoadOrStore[go.shape.*internal/abi.Type,go.shape.interface {}]"
	ssaName := "(*internal/sync.HashTrieMap[*internal/abi.Type, any]).LoadOrStore[*internal/abi.Type any]"

	gotRuntime := normalizedFuncName(runtimeName)
	gotSSA := normalizedFuncName(ssaName)

	if gotRuntime != gotSSA {
		t.Fatalf("normalized names differ:\nruntime: %s\nssa:     %s", gotRuntime, gotSSA)
	}
}

func TestAddExtraEdgeSkipsOnceDoSlowCaller(t *testing.T) {
	caller := &UnifiedNode{Key: "(*sync.Once).doSlow"}
	target := &UnifiedNode{Key: "time.initLocal"}

	unified := &UnifiedCallGraph{
		Nodes: map[string]*UnifiedNode{
			caller.Key: caller,
			target.Key: target,
		},
		Syscalls: map[string][]int{},
	}

	AddExtraEdge(
		unified,
		map[string]CallInfo{
			"sync.(*Once).doSlow": {
				Callee: []ExtraCallTarget{{RuntimeName: "time.initLocal"}},
			},
		},
		"",
	)

	if len(caller.Out) != 0 {
		t.Fatalf("expected no EXTRA edges to be added for sync.Once.doSlow, got %d", len(caller.Out))
	}
}

func TestExtraRuntimeNameCandidatesSkipTypePseudoTargets(t *testing.T) {
	candidates := extraRuntimeNameCandidates("type:.addrDetail", "")
	if len(candidates) != 0 {
		t.Fatalf("expected type pseudo target to be ignored, got %v", candidates)
	}
}

func TestAddExtraEdgePrefersInstantiatedCallerAtSameSourcePosition(t *testing.T) {
	extraCallerCache = make(map[string]string)
	extraCalleeCache = make(map[string]string)

	generic := &UnifiedNode{
		Key:           "sync.OnceValue$1$1",
		HasSSA:        true,
		Pos:           "/tmp/oncefunc.go:58:13",
		IsAnonymous:   true,
		SyscallBitSet: bitset.New(512),
	}
	instantiated := &UnifiedNode{
		Key:           "sync.OnceValue[error]$1$1",
		HasSSA:        true,
		Pos:           "/tmp/oncefunc.go:58:13",
		IsAnonymous:   true,
		SyscallBitSet: bitset.New(512),
	}
	callee := &UnifiedNode{
		Key:           "os.checkPidfd",
		HasSSA:        true,
		Pos:           "/tmp/pidfd.go:165:6",
		SyscallBitSet: bitset.New(512),
	}
	decoyCaller := &UnifiedNode{
		Key:           "sync.OnceValue[bool]$1$1",
		HasSSA:        true,
		Pos:           "/tmp/oncefunc.go:58:13",
		IsAnonymous:   true,
		SyscallBitSet: bitset.New(512),
	}
	decoyCallee := &UnifiedNode{
		Key:           "internal/poll.init$1",
		HasSSA:        true,
		Pos:           "/tmp/poll.go:10:6",
		SyscallBitSet: bitset.New(512),
	}

	linkTestNodes(instantiated, callee, "vta", &VTAEdgeInfo{
		HasSite:       true,
		IsDynamicFunc: true,
		SiteLine:      66,
		SiteCol:       18,
	})
	linkTestNodes(decoyCaller, decoyCallee, "vta", &VTAEdgeInfo{
		HasSite:       true,
		IsDynamicFunc: true,
		SiteLine:      66,
		SiteCol:       18,
	})

	unified := &UnifiedCallGraph{
		Nodes: map[string]*UnifiedNode{
			generic.Key:      generic,
			instantiated.Key: instantiated,
			callee.Key:       callee,
			decoyCaller.Key:  decoyCaller,
			decoyCallee.Key:  decoyCallee,
		},
		Syscalls: map[string][]int{},
	}

	AddExtraEdge(unified, map[string]CallInfo{
		"os.init.OnceValue[go.shape.interface { Error() string }].func2.1": {
			File: "/tmp/oncefunc.go",
			Line: 58,
			Col:  13,
			Callee: []ExtraCallTarget{{
				RuntimeName:  "os.checkPidfd",
				CallsiteLine: 66,
				CallsiteCol:  18,
			}},
		},
	}, "")

	if hasRetainedUnifiedEdge(generic, callee) {
		t.Fatalf("unexpected EXTRA edge attached to generic caller")
	}
	if !hasRetainedUnifiedEdge(instantiated, callee) {
		t.Fatalf("expected EXTRA edge attached to instantiated caller")
	}
}

func TestGetCallerNodePrefersDirectNamedMatchOverSourceGuess(t *testing.T) {
	direct := &UnifiedNode{
		Key:           "os.pidfdWorks",
		HasSSA:        true,
		Pos:           "/tmp/pidfd_linux.go:141:6",
		SyscallBitSet: bitset.New(512),
	}
	decoy := &UnifiedNode{
		Key:           "os.ensurePidfd",
		HasSSA:        true,
		Pos:           "/tmp/pidfd_linux.go:141:6",
		SyscallBitSet: bitset.New(512),
	}

	unified := &UnifiedCallGraph{
		Nodes: map[string]*UnifiedNode{
			direct.Key: direct,
			decoy.Key:  decoy,
		},
		Syscalls: map[string][]int{},
	}

	got := getCallerNode("os.pidfdWorks", CallInfo{
		File: "/tmp/pidfd_linux.go",
		Line: 141,
		Col:  6,
	}, unified, "")
	if got == nil {
		t.Fatal("getCallerNode returned nil")
	}
	if got.Key != direct.Key {
		t.Fatalf("expected direct named caller %q, got %q", direct.Key, got.Key)
	}
}
