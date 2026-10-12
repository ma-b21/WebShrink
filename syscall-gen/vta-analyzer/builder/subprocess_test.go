package builder

import (
	"os"
	"path/filepath"
	"testing"
)

func tracePathFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	scenarioDir := filepath.Join(root, "experiments", "sample-app")
	for _, dir := range []string{filepath.Join(root, "go-tesec"), filepath.Join(root, "syscall-gen"), filepath.Join(scenarioDir, "cli", "server")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	target := filepath.Join(scenarioDir, "cli", "server", "main.go")
	if err := os.WriteFile(target, []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	return root, scenarioDir
}

func TestNormalizeTraceSourcePathRewritesMigratedWorkspacePrefix(t *testing.T) {
	root, scenarioDir := tracePathFixture(t)
	t.Setenv("WEBSHRINK_WORKSPACE_ROOT", root)
	oldPath := "/opt/legacy/webshrink/experiments/sample-app/cli/server/main.go"
	got := normalizeTraceSourcePath(oldPath)
	want := filepath.Join(scenarioDir, "cli", "server", "main.go")
	if got != want {
		t.Fatalf("unexpected rewritten path: got=%q want=%q", got, want)
	}
}

func TestNormalizeTraceSourcePathFromScenarioWorkingDir(t *testing.T) {
	_, scenarioDir := tracePathFixture(t)
	t.Setenv("WEBSHRINK_WORKSPACE_ROOT", "")
	t.Chdir(scenarioDir)
	oldPath := "/opt/legacy/webshrink/experiments/sample-app/cli/server/main.go"
	got := normalizeTraceSourcePath(oldPath)
	want := filepath.Join(scenarioDir, "cli", "server", "main.go")
	if got != want {
		t.Fatalf("unexpected rewritten path from scenario dir: got=%q want=%q", got, want)
	}
}

func TestInferStdlibSrcRootFromPath(t *testing.T) {
	root := t.TempDir()
	srcRoot := filepath.Join(root, "go-tesec", "src")
	for _, dir := range []string{
		filepath.Join(srcRoot, "runtime"),
		filepath.Join(srcRoot, "sync"),
		filepath.Join(srcRoot, "net", "http"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	target := filepath.Join(srcRoot, "net", "http", "server.go")
	if err := os.WriteFile(target, []byte("package http\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	got := inferStdlibSrcRootFromPath(target)
	if got != srcRoot {
		t.Fatalf("unexpected inferred stdlib src root: got=%q want=%q", got, srcRoot)
	}
}
