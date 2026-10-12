package whitelist

import (
	"errors"
	"testing"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

func TestApplyFuncInjectsPrologue(t *testing.T) {
	fn := newTestFunc("example.com/whitelist/apply", "applypkg", "Handler", []*types.Type{types.Types[types.TINT]}, nil)
	cfg := &base.WhitelistConfig{
		FunctionIDs: map[string]uint32{"example.com/whitelist/apply.Handler": 99},
	}
	parsed := parsedSignature{
		params: []*types.Type{types.Types[types.TINT]},
	}
	pushStub := newRuntimeStub("PushWhitelist", []*types.Type{types.Types[types.TUINT32]}, nil)
	popStub := newRuntimeStub("PopWhitelist", nil, nil)

	applyFunc(fn, cfg, []parsedSignature{parsed}, pushStub, popStub)

	if !fn.HasDefer() {
		t.Fatalf("expected function to be marked as having defer")
	}
	if got := len(fn.Body); got != 3 {
		t.Fatalf("expected 3 statements in body, got %d", got)
	}
	pushCall, ok := fn.Body[0].(*ir.CallExpr)
	if !ok {
		t.Fatalf("first statement is not a call expression: %T", fn.Body[0])
	}
	if pushCall.Fun != pushStub {
		t.Fatalf("push call is not wired to runtime stub")
	}
	deferStmt, ok := fn.Body[1].(*ir.GoDeferStmt)
	if !ok {
		t.Fatalf("second statement is not a defer: %T", fn.Body[1])
	}
	popCall, ok := deferStmt.Call.(*ir.CallExpr)
	if !ok {
		t.Fatalf("defer payload is not a call expression: %T", deferStmt.Call)
	}
	if popCall.Fun != popStub {
		t.Fatalf("pop call is not wired to runtime stub")
	}
}

func TestApplyFuncSkipsOnSignatureMismatch(t *testing.T) {
	fn := newTestFunc("example.com/whitelist/apply", "applypkg", "Handler", []*types.Type{types.Types[types.TINT]}, nil)
	cfg := &base.WhitelistConfig{}
	parsed := parsedSignature{
		params: []*types.Type{types.Types[types.TINT], types.Types[types.TSTRING]},
	}
	pushStub := newRuntimeStub("PushWhitelist", []*types.Type{types.Types[types.TUINT32]}, nil)
	popStub := newRuntimeStub("PopWhitelist", nil, nil)

	applyFunc(fn, cfg, []parsedSignature{parsed}, pushStub, popStub)

	if fn.HasDefer() {
		t.Fatalf("unexpected instrumentation on signature mismatch")
	}
	if len(fn.Body) != 1 {
		t.Fatalf("function body should be untouched when signatures mismatch")
	}
}

func TestApplyFuncSkipsUnsafeContext(t *testing.T) {
	cases := []struct {
		name             string
		pragma           ir.PragmaFlag
		compilingRuntime bool
	}{
		{name: "nosplit", pragma: ir.Nosplit},
		{name: "systemstack", pragma: ir.Systemstack},
		{name: "runtime compile", compilingRuntime: true},
	}

	originalCompilingRuntime := base.Flag.CompilingRuntime
	defer func() {
		base.Flag.CompilingRuntime = originalCompilingRuntime
	}()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base.Flag.CompilingRuntime = tc.compilingRuntime

			fn := newTestFunc("example.com/whitelist/apply", "applypkg", "Handler", []*types.Type{types.Types[types.TINT]}, nil)
			fn.Pragma = tc.pragma
			beforeLen := len(fn.Body)

			cfg := &base.WhitelistConfig{
				FunctionIDs: map[string]uint32{"example.com/whitelist/apply.Handler": 7},
			}
			pushStub := newRuntimeStub("PushWhitelist", []*types.Type{types.Types[types.TUINT32]}, nil)
			popStub := newRuntimeStub("PopWhitelist", nil, nil)

			applyFunc(fn, cfg, nil, pushStub, popStub)

			if fn.HasDefer() {
				t.Fatalf("unexpected instrumentation in unsafe context")
			}
			if got := len(fn.Body); got != beforeLen {
				t.Fatalf("function body should be untouched in unsafe context: got %d, want %d", got, beforeLen)
			}
		})
	}
}

func TestMatchesSignatureAny(t *testing.T) {
	fn := newTestFunc("example.com/whitelist/apply", "applypkg", "Handler", []*types.Type{types.Types[types.TINT], types.Types[types.TSTRING]}, []*types.Type{types.Types[types.TINT]})
	parsed := parsedSignature{
		params:     []*types.Type{types.Types[types.TINT], nil},
		paramsAny:  []bool{false, true},
		results:    []*types.Type{nil},
		resultsAny: []bool{true},
	}
	if !matchesSignature(fn, parsed) {
		t.Fatalf("expected signature match with any")
	}
}

func TestShouldIgnoreSignatureParseError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "unknown package", err: errors.New("unknown package \"x/y\""), want: true},
		{name: "unknown type", err: errors.New("unknown type \"T\""), want: true},
		{name: "invalid type expr", err: errors.New("invalid type expression: whitelist_type_expr.go:1:1: syntax error"), want: true},
		{name: "failed parse", err: errors.New("failed to parse type expression"), want: true},
		{name: "empty", err: errors.New("empty type expression"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldIgnoreSignatureParseError(tc.err); got != tc.want {
				t.Fatalf("shouldIgnoreSignatureParseError()=%v, want %v, err=%v", got, tc.want, tc.err)
			}
		})
	}
}

func newTestFunc(pkgPath, pkgName, name string, params, results []*types.Type) *ir.Func {
	pkg := types.NewPkg(pkgPath, pkgName)
	sym := pkg.Lookup(name)
	sig := types.NewSignature(nil, makeFields(params), makeFields(results))
	fn := ir.NewFunc(src.NoXPos, src.NoXPos, sym, sig)
	fn.Body.Append(ir.NewReturnStmt(src.NoXPos, nil))
	return fn
}

func newRuntimeStub(name string, params, results []*types.Type) *ir.Name {
	pkg := types.NewPkg("runtime", "runtime")
	sym := pkg.Lookup(name)
	sig := types.NewSignature(nil, makeFields(params), makeFields(results))
	return ir.NewFunc(src.NoXPos, src.NoXPos, sym, sig).Nname
}

func makeFields(list []*types.Type) []*types.Field {
	if len(list) == 0 {
		return nil
	}
	fields := make([]*types.Field, len(list))
	for i, typ := range list {
		fields[i] = types.NewField(src.NoXPos, nil, typ)
	}
	return fields
}
