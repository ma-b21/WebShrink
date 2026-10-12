package builder

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

type sourcePosition struct {
	File string
	Line int
	Col  int
}

type wrappedValueTarget struct {
	Pos          sourcePosition
	ResolvedName string
}

type wrappedValueLookupResult struct {
	target wrappedValueTarget
	ok     bool
}

var wrappedValueLookupCache sync.Map

func parseSourcePosition(pos string) (sourcePosition, bool) {
	pos = strings.TrimSpace(pos)
	if pos == "" {
		return sourcePosition{}, false
	}

	lastColon := strings.LastIndex(pos, ":")
	if lastColon == -1 {
		return sourcePosition{}, false
	}
	col, err := strconv.Atoi(pos[lastColon+1:])
	if err != nil {
		return sourcePosition{}, false
	}

	secondLastColon := strings.LastIndex(pos[:lastColon], ":")
	if secondLastColon == -1 {
		return sourcePosition{}, false
	}
	line, err := strconv.Atoi(pos[secondLastColon+1 : lastColon])
	if err != nil {
		return sourcePosition{}, false
	}

	filePath := normalizeTraceSourcePath(pos[:secondLastColon])
	if filePath == "" {
		return sourcePosition{}, false
	}

	return sourcePosition{
		File: filepath.Clean(filePath),
		Line: line,
		Col:  col,
	}, true
}

func parseWrappedFuncValueName(rawTarget string) (string, bool) {
	rawTarget = strings.TrimSpace(rawTarget)
	if !strings.HasPrefix(rawTarget, "*") {
		return "", false
	}
	rawTarget = strings.TrimPrefix(rawTarget, "*")
	if rawTarget == "" {
		return "", false
	}
	if looksLikeSSATemporary(rawTarget) {
		return "", false
	}

	for i, r := range rawTarget {
		if r == '_' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r)) {
			continue
		}
		return "", false
	}

	return rawTarget, true
}

func looksLikeSSATemporary(name string) bool {
	if name == "" {
		return false
	}
	if len(name) >= 2 && name[0] == 't' {
		allDigits := true
		for i := 1; i < len(name); i++ {
			if name[i] < '0' || name[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

func resolveWrappedFuncValueTarget(caller *UnifiedNode, rawTarget string, unifiedCG *UnifiedCallGraph) *UnifiedNode {
	if caller == nil || unifiedCG == nil {
		return nil
	}

	valueName, ok := parseWrappedFuncValueName(rawTarget)
	if !ok {
		return nil
	}

	callerPos, ok := parseSourcePosition(caller.Pos)
	if !ok {
		return nil
	}

	target, ok := lookupWrappedValueTarget(callerPos.File, valueName)
	if !ok {
		return nil
	}

	if target.Pos.File != "" && target.Pos.Line > 0 {
		if node := findNodeBySourcePosition(unifiedCG, target.Pos, true); node != nil {
			return node
		}
		if node := findNodeBySourcePosition(unifiedCG, target.Pos, false); node != nil {
			return node
		}
	}

	if target.ResolvedName != "" {
		return resolveNamedWrappedTarget(caller.Key, target.ResolvedName, unifiedCG)
	}

	return nil
}

func lookupWrappedValueTarget(callerFile string, valueName string) (wrappedValueTarget, bool) {
	cacheKey := filepath.Clean(callerFile) + "\x00" + valueName
	if cached, ok := wrappedValueLookupCache.Load(cacheKey); ok {
		result := cached.(wrappedValueLookupResult)
		return result.target, result.ok
	}

	dir := filepath.Dir(callerFile)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(info fs.FileInfo) bool {
		name := info.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, 0)
	if err != nil || len(pkgs) == 0 {
		wrappedValueLookupCache.Store(cacheKey, wrappedValueLookupResult{})
		return wrappedValueTarget{}, false
	}

	var target wrappedValueTarget
	found := false

	files := collectPackageFiles(pkgs, callerFile)
	for _, file := range files {
		if next, ok := findWrappedValueTargetInFile(fset, file, valueName); ok {
			target = next
			found = true
		}
	}

	wrappedValueLookupCache.Store(cacheKey, wrappedValueLookupResult{target: target, ok: found})
	return target, found
}

func collectPackageFiles(pkgs map[string]*ast.Package, callerFile string) []*ast.File {
	callerFile = filepath.Clean(callerFile)
	var matched []*ast.File
	var fallback []*ast.File

	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		names := make([]string, 0, len(pkg.Files))
		for name := range pkg.Files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			file := pkg.Files[name]
			if file == nil {
				continue
			}
			fallback = append(fallback, file)
			if filepath.Clean(name) == callerFile {
				matched = append(matched, file)
			}
		}
	}

	if len(matched) > 0 {
		return matched
	}
	return fallback
}

func findWrappedValueTargetInFile(fset *token.FileSet, file *ast.File, valueName string) (wrappedValueTarget, bool) {
	var target wrappedValueTarget
	found := false

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if next, ok := matchValueSpecTarget(fset, valueSpec, valueName); ok {
					target = next
					found = true
				}
			}
		case *ast.FuncDecl:
			if d.Name == nil || d.Name.Name != "init" || d.Body == nil {
				continue
			}
			if next, ok := matchInitAssignments(fset, d.Body, valueName); ok {
				target = next
				found = true
			}
		}
	}

	return target, found
}

func matchValueSpecTarget(fset *token.FileSet, spec *ast.ValueSpec, valueName string) (wrappedValueTarget, bool) {
	if spec == nil {
		return wrappedValueTarget{}, false
	}

	for idx, name := range spec.Names {
		if name == nil || name.Name != valueName {
			continue
		}
		valueExpr := matchedValueExpr(spec.Values, idx)
		if valueExpr == nil {
			return wrappedValueTarget{}, false
		}
		return wrappedTargetFromExpr(fset, valueExpr)
	}

	return wrappedValueTarget{}, false
}

func matchInitAssignments(fset *token.FileSet, body *ast.BlockStmt, valueName string) (wrappedValueTarget, bool) {
	var target wrappedValueTarget
	found := false

	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for idx, lhs := range n.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || ident.Name != valueName {
					continue
				}
				valueExpr := matchedValueExpr(n.Rhs, idx)
				if valueExpr == nil {
					continue
				}
				if next, ok := wrappedTargetFromExpr(fset, valueExpr); ok {
					target = next
					found = true
				}
			}
		}
		return true
	})

	return target, found
}

func matchedValueExpr(values []ast.Expr, idx int) ast.Expr {
	if len(values) == 0 {
		return nil
	}
	if idx < len(values) {
		return values[idx]
	}
	if len(values) == 1 {
		return values[0]
	}
	return nil
}

func wrappedTargetFromExpr(fset *token.FileSet, expr ast.Expr) (wrappedValueTarget, bool) {
	switch v := expr.(type) {
	case *ast.FuncLit:
		pos := fset.Position(v.Type.Func)
		return wrappedValueTarget{
			Pos: sourcePosition{
				File: filepath.Clean(normalizeTraceSourcePath(pos.Filename)),
				Line: pos.Line,
				Col:  pos.Column,
			},
		}, true
	case *ast.Ident:
		return wrappedValueTarget{ResolvedName: v.Name}, true
	}

	return wrappedValueTarget{}, false
}

func findNodeBySourcePosition(unifiedCG *UnifiedCallGraph, target sourcePosition, requireExactCol bool) *UnifiedNode {
	if unifiedCG == nil || target.File == "" || target.Line <= 0 {
		return nil
	}

	lookup := unifiedCG.getNodeLookup()
	if lookup == nil {
		return nil
	}

	key := sourcePositionKey(target.File, target.Line, 0)
	candidates := lookup.byPosLine[key]
	if requireExactCol && target.Col > 0 {
		candidates = lookup.byPosExact[sourcePositionKey(target.File, target.Line, target.Col)]
	}

	var best *UnifiedNode
	for _, candidate := range candidates {
		if candidate == nil || candidate.Pos == "" {
			continue
		}
		pos, ok := parseSourcePosition(candidate.Pos)
		if !ok {
			continue
		}
		if filepath.Clean(pos.File) != filepath.Clean(target.File) || pos.Line != target.Line {
			continue
		}
		if requireExactCol && target.Col > 0 && pos.Col != target.Col {
			continue
		}
		if best == nil || (candidate.IsAnonymous && !best.IsAnonymous) {
			best = candidate
		}
	}

	return best
}

func resolveNamedWrappedTarget(callerKey string, rawTarget string, unifiedCG *UnifiedCallGraph) *UnifiedNode {
	bestScore := 0
	var best *UnifiedNode
	ambiguous := false

	for _, candidate := range wrappedTargetCandidates(callerKey, rawTarget, unifiedCG) {
		if candidate == nil {
			continue
		}
		score := scoreWrappedTargetCandidate(callerKey, rawTarget, candidate.Key)
		if score == 0 {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = candidate
			ambiguous = false
			continue
		}
		if score == bestScore && best != nil && best.Key != candidate.Key {
			ambiguous = true
		}
	}

	if ambiguous {
		return nil
	}
	return best
}
