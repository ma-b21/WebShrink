package builder

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSelectTraceAnchorIndexPrefersDeepestExistingLaunchFrame(t *testing.T) {
	stackKeys := []string{
		"github.com/gogs/git-module.(*Command).RunInDirPipelineWithTimeout",
		"github.com/gogs/git-module.Clone",
		"gogs.io/gogs/internal/db.UpdateLocalCopyBranch",
		"(*gogs.io/gogs/internal/db.Repository).UploadRepoFiles",
		"gogs.io/gogs/internal/route/repo.UploadFilePost",
	}
	matched := []int{4}
	dagKeys := map[string]struct{}{
		"github.com/gogs/git-module.Clone":                       {},
		"gogs.io/gogs/internal/db.UpdateLocalCopyBranch":         {},
		"(*gogs.io/gogs/internal/db.Repository).UploadRepoFiles": {},
		"gogs.io/gogs/internal/route/repo.UploadFilePost":        {},
	}

	if got := selectTraceAnchorIndex(stackKeys, matched, dagKeys); got != 1 {
		t.Fatalf("expected deepest existing launch frame index 1, got %d", got)
	}
}

func TestSelectTraceAnchorIndexFallsBackToHandlerWhenNoDeeperNodeExists(t *testing.T) {
	stackKeys := []string{
		"github.com/example/missing.Wrapper",
		"github.com/example/missing.Helper",
		"app.Handler",
	}
	matched := []int{2}
	dagKeys := map[string]struct{}{
		"app.Handler": {},
	}

	if got := selectTraceAnchorIndex(stackKeys, matched, dagKeys); got != 2 {
		t.Fatalf("expected handler fallback index 2, got %d", got)
	}
}

func TestSelectTraceAnchorIndexWithoutHandlerUsesDeepestExistingBusinessFrame(t *testing.T) {
	stackKeys := []string{
		"github.com/example/missing.Wrapper",
		"app.Worker",
		"app.Parent",
	}
	dagKeys := map[string]struct{}{
		"app.Worker": {},
		"app.Parent": {},
	}

	if got := selectTraceAnchorIndex(stackKeys, nil, dagKeys); got != 1 {
		t.Fatalf("expected deepest existing business frame index 1, got %d", got)
	}
}

func TestSelectTraceAnchorIndexKeepsCurrentBehaviorWithoutDAGKeys(t *testing.T) {
	stackKeys := []string{
		"github.com/example/missing.Wrapper",
		"app.Handler",
	}
	matched := []int{1}

	if got := selectTraceAnchorIndex(stackKeys, matched, nil); got != 1 {
		t.Fatalf("expected handler fallback index 1, got %d", got)
	}
}

func TestTokenizeSubcommandArgsDropsBinaryFlagsAndPaths(t *testing.T) {
	got := tokenizeSubcommandArgs("gogs hook --config=/tmp/app.ini post-receive")
	want := []string{"hook", "post", "receive"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected tokens: got %v want %v", got, want)
	}
}

func TestSelectSelfReexecRuntimeTargetPrefersUniqueSubcommandMatch(t *testing.T) {
	parentMap := map[int]int{
		300: 200,
		200: 100,
	}
	procMetaByPID := map[int]procMeta{
		100: {Pid: 100, ExePath: "/srv/gogs/gogs", Cmdline: "gogs web"},
		200: {Pid: 200, PPid: 100, ExePath: "/srv/gogs/gogs", Cmdline: "gogs hook --config=/tmp/app.ini post-receive"},
		300: {Pid: 300, PPid: 200, ExePath: "/usr/bin/curl", Cmdline: "curl http://127.0.0.1"},
	}
	dagKeys := map[string]struct{}{
		"gogs.io/gogs/internal/cmd.runHookPostReceive": {},
		"gogs.io/gogs/internal/cmd.runHookPreReceive":  {},
	}

	if got := selectSelfReexecRuntimeTarget(300, 100, parentMap, procMetaByPID, dagKeys); got != "gogs.io/gogs/internal/cmd.runHookPostReceive" {
		t.Fatalf("unexpected runtime target: got %q", got)
	}
}

func TestSelectSelfReexecRuntimeTargetRequiresUniqueMatch(t *testing.T) {
	parentMap := map[int]int{
		300: 200,
		200: 100,
	}
	procMetaByPID := map[int]procMeta{
		100: {Pid: 100, ExePath: "/srv/app/app", Cmdline: "app serve"},
		200: {Pid: 200, PPid: 100, ExePath: "/srv/app/app", Cmdline: "app hook"},
		300: {Pid: 300, PPid: 200, ExePath: "/usr/bin/curl", Cmdline: "curl http://127.0.0.1"},
	}
	dagKeys := map[string]struct{}{
		"example.runHookPostReceive": {},
		"example.runHookUpdate":      {},
	}

	if got := selectSelfReexecRuntimeTarget(300, 100, parentMap, procMetaByPID, dagKeys); got != "" {
		t.Fatalf("expected no runtime target for ambiguous match, got %q", got)
	}
}

func TestSelectSelfReexecRuntimeTargetPrefersWorkspaceReentryOverExternalSubcommand(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "webshrink")
	for _, dir := range []string{"go-tesec", "experiments", "syscall-gen"} {
		if err := os.MkdirAll(filepath.Join(workspace, dir), 0o755); err != nil {
			t.Fatalf("mkdir workspace directory %s: %v", dir, err)
		}
	}
	t.Setenv("WEBSHRINK_WORKSPACE_ROOT", workspace)

	parentMap := map[int]int{
		500: 400,
		400: 300,
		300: 200,
		200: 100,
	}
	procMetaByPID := map[int]procMeta{
		100: {Pid: 100, ExePath: "/usr/bin/git", Cmdline: "git push origin master"},
		200: {Pid: 200, PPid: 100, ExePath: "/usr/bin/dash", Cmdline: "sh -c git-receive-pack"},
		300: {Pid: 300, PPid: 200, ExePath: "/usr/bin/bash", Cmdline: "bash hooks/post-receive"},
		400: {Pid: 400, PPid: 300, ExePath: filepath.Join(workspace, "experiments/CVE-2022-0415/gogs-0.12.5/gogs"), Cmdline: "gogs hook --config=/tmp/app.ini post-receive"},
		500: {Pid: 500, PPid: 400, ExePath: "/usr/lib/git-core/git", Cmdline: "git update-server-info"},
	}
	dagKeys := map[string]struct{}{
		"gogs.io/gogs/internal/cmd.runHookPostReceive": {},
		"gogs.io/gogs/internal/route/repo.updateServerInfo": {},
	}

	if got := selectSelfReexecRuntimeTarget(500, 100, parentMap, procMetaByPID, dagKeys); got != "gogs.io/gogs/internal/cmd.runHookPostReceive" {
		t.Fatalf("unexpected runtime target: got %q", got)
	}
}
