// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"testing"
)

func TestSimplifyFuncName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "no package split",
			in:   "plain",
			want: "plain",
		},
		{
			name: "simple function",
			in:   "pkg/path.f",
			want: "pkg/path.f",
		},
		{
			name: "compiler generated init symbol",
			in:   "pkg/path.init.0",
			want: "pkg/path.init.0",
		},
		{
			name: "value receiver method",
			in:   "pkg/path.Type.Method",
			want: "pkg/path.Type.Method",
		},
		{
			name: "pointer receiver method",
			in:   "pkg/path.(*Type).Method",
			want: "pkg/path.(*Type).Method",
		},
		{
			name: "strip method-value wrapper suffix on method",
			in:   "pkg/path.(*Type).Method-fm",
			want: "pkg/path.(*Type).Method",
		},
		{
			name: "strip method-value wrapper suffix on nested method closure",
			in:   "pkg/path.(*Type).Method-fm.func1",
			want: "pkg/path.(*Type).Method.func1",
		},
		{
			name: "generic receiver method",
			in:   "pkg/path.(*Type[int]).Method",
			want: "pkg/path.(*Type[int]).Method",
		},
		{
			name: "drop upper named nesting for method then function",
			in:   "pkg/path.(*Type).Method.nested",
			want: "pkg/path.nested",
		},
		{
			name: "single closure on function",
			in:   "pkg/path.outer.func1",
			want: "pkg/path.outer.func1",
		},
		{
			name: "nested closure chain on function",
			in:   "pkg/path.outer.func1.func2",
			want: "pkg/path.outer.func1.func2",
		},
		{
			name: "single closure on method",
			in:   "pkg/path.(*Type).Method.func1",
			want: "pkg/path.(*Type).Method.func1",
		},
		{
			name: "nested closure chain on method",
			in:   "pkg/path.(*Type).Method.func1.func2",
			want: "pkg/path.(*Type).Method.func1.func2",
		},
		{
			name: "closure on nested named function",
			in:   "pkg/path.(*Type).Method.nested.func2",
			want: "pkg/path.nested.func2",
		},
		{
			name: "closure chain on nested named function",
			in:   "pkg/path.(*Type).Method.nested.func2.func3",
			want: "pkg/path.nested.func2.func3",
		},
		{
			name: "closure numeric continuation on method",
			in:   "github.com/open-policy-agent/opa/ast.(*Compiler).rewritePrintCalls.func1.1",
			want: "github.com/open-policy-agent/opa/ast.(*Compiler).rewritePrintCalls.func1.1",
		},
		{
			name: "closure numeric continuation with branch index",
			in:   "github.com/open-policy-agent/opa/ast.(*Compiler).rewriteRegoMetadataCalls.func1.2",
			want: "github.com/open-policy-agent/opa/ast.(*Compiler).rewriteRegoMetadataCalls.func1.2",
		},
		{
			name: "closure numeric continuation on function",
			in:   "github.com/open-policy-agent/opa/ast.BenchmarkObjectConstruction.func1.1.1",
			want: "github.com/open-policy-agent/opa/ast.BenchmarkObjectConstruction.func1.1.1",
		},
		{
			name: "deep nesting keep only bottom named plus closure suffix",
			in:   "pkg/path.A.B.C.func4",
			want: "pkg/path.C.func4",
		},
		{
			name: "escaped package prefix remains as-is in runtime",
			in:   "example%2ecom/p.k",
			want: "example%2ecom/p.k",
		},
		{
			name: "strip -fm from user reported symbol",
			in:   "github.com/open-policy-agent/opa/ast.(*rewriteNestedHeadVarLocalTransform).Visit-fm",
			want: "github.com/open-policy-agent/opa/ast.(*rewriteNestedHeadVarLocalTransform).Visit",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := runtime.SimplifyFuncNameForTest(tc.in)
			if got != tc.want {
				t.Fatalf("SimplifyFuncNameForTest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
