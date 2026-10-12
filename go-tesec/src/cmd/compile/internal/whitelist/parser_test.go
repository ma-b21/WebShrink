package whitelist

import (
	"os"
	"testing"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"cmd/internal/sys"
)

func TestMain(m *testing.M) {
	types.PtrSize = 8
	types.RegSize = 8
	types.MaxWidth = 1 << 50
	base.Ctxt = &obj.Link{Arch: &obj.LinkArch{Arch: &sys.Arch{Alignment: 1, CanMergeLoads: true}}}
	typecheck.InitUniverse()
	os.Exit(m.Run())
}

func TestParseTypeLiteralBasic(t *testing.T) {
	typ, err := parseTypeLiteral("func(int, string) error")
	if err != nil {
		t.Fatalf("parseTypeLiteral failed: %v", err)
	}
	if typ.NumParams() != 2 {
		t.Fatalf("expected 2 params, got %d", typ.NumParams())
	}
	if typ.NumResults() != 1 {
		t.Fatalf("expected 1 result, got %d", typ.NumResults())
	}
	if typ.Param(0).Type != types.Types[types.TINT] {
		t.Fatalf("param0 type mismatch: %v", typ.Param(0).Type)
	}
	if typ.Param(1).Type != types.Types[types.TSTRING] {
		t.Fatalf("param1 type mismatch: %v", typ.Param(1).Type)
	}
	if typ.Result(0).Type != types.ErrorType {
		t.Fatalf("result type mismatch: %v", typ.Result(0).Type)
	}
}

func TestParseTypeLiteralVariadicAndChan(t *testing.T) {
	typ, err := parseTypeLiteral("func(chan<- int, <-chan string, ...[]byte)")
	if err != nil {
		t.Fatalf("parseTypeLiteral failed: %v", err)
	}
	if typ.NumParams() != 3 {
		t.Fatalf("expected 3 params, got %d", typ.NumParams())
	}
	chanSend := typ.Param(0).Type
	if !chanSend.IsChan() || chanSend.ChanDir() != types.Csend {
		t.Fatalf("expected send-only chan, got %v", chanSend)
	}
	chanRecv := typ.Param(1).Type
	if !chanRecv.IsChan() || chanRecv.ChanDir() != types.Crecv {
		t.Fatalf("expected recv-only chan, got %v", chanRecv)
	}
	variadic := typ.Param(2)
	if !variadic.IsDDD() {
		t.Fatalf("expected variadic parameter")
	}
	if variadic.Type.Elem() != types.ByteType {
		t.Fatalf("expected variadic []byte, got %v", variadic.Type)
	}
}

func TestParseTypeLiteralPackagePath(t *testing.T) {
	pkgPath := "example.com/whitelist/testpkg"
	reqType := registerMockType(t, pkgPath, "testpkg", "Request")
	resType := registerMockType(t, pkgPath, "testpkg", "Response")

	expr := "func(*" + pkgPath + ".Request) *" + pkgPath + ".Response"
	typ, err := parseTypeLiteral(expr)
	if err != nil {
		t.Fatalf("parseTypeLiteral failed: %v", err)
	}
	if typ.NumParams() != 1 || typ.NumResults() != 1 {
		t.Fatalf("unexpected params/results count")
	}
	param := typ.Param(0).Type
	if !param.IsPtr() || param.Elem() != reqType {
		t.Fatalf("param does not match registered type")
	}
	result := typ.Result(0).Type
	if !result.IsPtr() || result.Elem() != resType {
		t.Fatalf("result does not match registered type")
	}
}

func TestRewriteTokenRequiresIdentifierSuffix(t *testing.T) {
	aliasToPath := make(map[string]string)
	pathToAlias := make(map[string]string)

	if got, ok := rewriteToken("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", aliasToPath, pathToAlias); ok {
		t.Fatalf("rewriteToken unexpectedly rewrote package path without type suffix: %q", got)
	}

	got, ok := rewriteToken("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp.middleware", aliasToPath, pathToAlias)
	if !ok {
		t.Fatalf("rewriteToken failed for valid pkg.Type token")
	}
	if got != "__whitelist_pkg0.middleware" {
		t.Fatalf("unexpected rewrite result: %q", got)
	}
}

func TestRewriteTokenImportPathWithHyphen(t *testing.T) {
	aliasToPath := make(map[string]string)
	pathToAlias := make(map[string]string)

	got, ok := rewriteToken("github.com/gin-gonic/gin.Context", aliasToPath, pathToAlias)
	if !ok {
		t.Fatalf("rewriteToken failed for import path containing hyphen")
	}
	if got != "__whitelist_pkg0.Context" {
		t.Fatalf("unexpected rewrite result: %q", got)
	}
	if aliasToPath["__whitelist_pkg0"] != "github.com/gin-gonic/gin" {
		t.Fatalf("unexpected alias mapping: %#v", aliasToPath)
	}
}

func registerMockType(t *testing.T, pkgPath, pkgName, typeName string) *types.Type {
	t.Helper()
	pkg := types.NewPkg(pkgPath, pkgName)
	sym := pkg.Lookup(typeName)
	name := ir.NewDeclNameAt(src.NoXPos, ir.OTYPE, sym)
	typ := types.NewStruct(nil)
	name.SetType(typ)
	name.SetTypecheck(1)
	sym.Def = name
	return typ
}
