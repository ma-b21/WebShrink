package builder

import "testing"

func linkTestNodes(caller, callee *UnifiedNode, source string, vta *VTAEdgeInfo) {
	edge := &UnifiedEdge{
		Caller: caller,
		Callee: callee,
		VTA:    vta,
		Source: source,
	}
	caller.Out = append(caller.Out, edge)
	callee.In = append(callee.In, edge)
}

func TestWrappedTargetCandidatesIndexing(t *testing.T) {
	ucg := NewUnifiedCallGraph()
	ucg.Nodes["github.com/example/pkg.Target"] = &UnifiedNode{Key: "github.com/example/pkg.Target"}
	ucg.Nodes["(*github.com/example/pkg.Widget).Run"] = &UnifiedNode{Key: "(*github.com/example/pkg.Widget).Run"}
	ucg.Nodes["caller$1"] = &UnifiedNode{Key: "caller$1", IsAnonymous: true}
	ucg.invalidateNodeLookup()

	candidates := wrappedTargetCandidates("caller", "Run", ucg)
	got := make(map[string]bool)
	for _, node := range candidates {
		got[node.Key] = true
	}

	for _, want := range []string{
		"(*github.com/example/pkg.Widget).Run",
		"caller$1",
	} {
		if !got[want] {
			t.Fatalf("wrappedTargetCandidates missing %q in %v", want, got)
		}
	}
}

func TestFindNodeBySourcePositionPrefersAnonymousCandidate(t *testing.T) {
	ucg := NewUnifiedCallGraph()
	ucg.Nodes["pkg.Named"] = &UnifiedNode{
		Key:         "pkg.Named",
		Pos:         "/tmp/example.go:12:3",
		HasSSA:      true,
		IsAnonymous: false,
	}
	ucg.Nodes["pkg.Named$1"] = &UnifiedNode{
		Key:         "pkg.Named$1",
		Pos:         "/tmp/example.go:12:3",
		HasSSA:      true,
		IsAnonymous: true,
	}
	ucg.invalidateNodeLookup()

	target := sourcePosition{File: "/tmp/example.go", Line: 12, Col: 3}
	got := findNodeBySourcePosition(ucg, target, true)
	if got == nil {
		t.Fatal("findNodeBySourcePosition returned nil")
	}
	if got.Key != "pkg.Named$1" {
		t.Fatalf("expected anonymous candidate, got %q", got.Key)
	}
}
