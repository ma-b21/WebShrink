package utils

import "testing"

func TestParseRuntimeNameWithMainPkgRewritesMainPackage(t *testing.T) {
	mainPkg := "github.com/example/app"

	pkgName, ssaName := ParseRuntimeNameWithMainPkg("main.(*Handler).ServeHTTP", mainPkg)
	if pkgName != mainPkg {
		t.Fatalf("unexpected package name: got %q want %q", pkgName, mainPkg)
	}

	wantSSA := "(*github.com/example/app.Handler).ServeHTTP"
	if ssaName != wantSSA {
		t.Fatalf("unexpected ssa name: got %q want %q", ssaName, wantSSA)
	}
}

func TestParseRuntimeNameWithMainPkgLeavesOtherPackagesUntouched(t *testing.T) {
	runtimeName := "github.com/canonical/lxd/lxd.networksPost"

	pkgName, ssaName := ParseRuntimeNameWithMainPkg(runtimeName, "github.com/example/app")
	if pkgName != "github.com/canonical/lxd/lxd" {
		t.Fatalf("unexpected package name: got %q", pkgName)
	}

	if ssaName != runtimeName {
		t.Fatalf("unexpected ssa name: got %q want %q", ssaName, runtimeName)
	}
}

func TestParseRuntimeNameWithMainPkgRewritesMainTopLevelFunction(t *testing.T) {
	mainPkg := "cvewebapp"

	pkgName, ssaName := ParseRuntimeNameWithMainPkg("main.healthzHandler", mainPkg)
	if pkgName != mainPkg {
		t.Fatalf("unexpected package name: got %q want %q", pkgName, mainPkg)
	}

	if ssaName != "cvewebapp.healthzHandler" {
		t.Fatalf("unexpected ssa name: got %q want %q", ssaName, "cvewebapp.healthzHandler")
	}
}

func TestParseRuntimeNameWithMainPkgCollapsesDuplicatedMainFunctionPrefix(t *testing.T) {
	mainPkg := "cvewebapp"

	pkgName, ssaName := ParseRuntimeNameWithMainPkg("main.main.policiesHandler.func1", mainPkg)
	if pkgName != mainPkg {
		t.Fatalf("unexpected package name: got %q want %q", pkgName, mainPkg)
	}

	if ssaName != "cvewebapp.policiesHandler$1" {
		t.Fatalf("unexpected ssa name: got %q want %q", ssaName, "cvewebapp.policiesHandler$1")
	}
}
