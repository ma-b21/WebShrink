package utils

import (
	"go/ast"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var funcIndexCache sync.Map

type functionIndex struct {
	exact              map[string]*ssa.Function
	normalized         map[string]*ssa.Function
	normalizedConflict map[string]bool
	canonical          map[string]*ssa.Function
	canonicalConflict  map[string]bool
}

// FindFunction resolves an exact or normalized SSA function name.
func FindFunction(prog *ssa.Program, pkgs []*packages.Package, funcName string) *ssa.Function {
	if prog == nil {
		return nil
	}
	if cached, ok := funcIndexCache.Load(prog); ok {
		return findIndexedFunction(cached.(*functionIndex), funcName)
	}

	index := newFunctionIndex()
	for fn := range ssautil.AllFunctions(prog) {
		indexFunction(index, fn.String(), fn)
	}
	actual, _ := funcIndexCache.LoadOrStore(prog, index)
	return findIndexedFunction(actual.(*functionIndex), funcName)
}

// FindAvailableFunctions lists the functions belonging to the supplied packages.
func FindAvailableFunctions(prog *ssa.Program, pkgs []*packages.Package) []string {
	// 遍历所有包
	seen := make(map[string]bool)
	var res []string
	for _, pkg := range pkgs {
		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		// 使用 AllFunctions 获取包中所有函数（包括闭包）
		for fn := range ssautil.AllFunctions(prog) {
			if fn.Pkg == ssaPkg {
				name := fn.String()
				if !seen[name] {
					res = append(res, name)
					seen[name] = true
				}
			}
		}
	}

	return res
}

func IsAnonymous(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	if fn.Synthetic != "" { // wrapper/thunk/init 等合成函数
		return false
	}
	if fn.Object() != nil { // 有声明对象 => 命名函数/方法
		return false
	}
	_, isLit := fn.Syntax().(*ast.FuncLit)
	return isLit
}

func GetFunctionPosition(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}

	pos := fn.Pos()
	if !pos.IsValid() {
		return ""
	}

	if fn.Prog == nil || fn.Prog.Fset == nil {
		return ""
	}

	return fn.Prog.Fset.Position(pos).String()
}

func newFunctionIndex() *functionIndex {
	return &functionIndex{
		exact:              make(map[string]*ssa.Function),
		normalized:         make(map[string]*ssa.Function),
		normalizedConflict: make(map[string]bool),
		canonical:          make(map[string]*ssa.Function),
		canonicalConflict:  make(map[string]bool),
	}
}

func indexFunction(index *functionIndex, funcName string, fn *ssa.Function) {
	if index == nil || funcName == "" || fn == nil {
		return
	}

	index.exact[funcName] = fn
	indexUnique(index.normalized, index.normalizedConflict, normalizedFuncName(funcName), fn)
	indexUnique(index.canonical, index.canonicalConflict, canonicalFuncName(funcName), fn)
}

func findIndexedFunction(index *functionIndex, funcName string) *ssa.Function {
	if index == nil || funcName == "" {
		return nil
	}

	if fn := index.exact[funcName]; fn != nil {
		return fn
	}

	if fn := lookupUnique(index.normalized, index.normalizedConflict, normalizedFuncName(funcName)); fn != nil {
		return fn
	}

	return lookupUnique(index.canonical, index.canonicalConflict, canonicalFuncName(funcName))
}

func indexUnique(index map[string]*ssa.Function, conflicts map[string]bool, key string, fn *ssa.Function) {
	if key == "" || fn == nil {
		return
	}
	if conflicts[key] {
		return
	}
	if existing, ok := index[key]; ok && existing != fn {
		delete(index, key)
		conflicts[key] = true
		return
	}
	index[key] = fn
}

func lookupUnique(index map[string]*ssa.Function, conflicts map[string]bool, key string) *ssa.Function {
	if key == "" || conflicts[key] {
		return nil
	}
	return index[key]
}

func stripBracketContent(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}

	return b.String()
}

func normalizeBracketContent(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
			b.WriteByte(s[i])
		case ']':
			if depth > 0 {
				depth--
			}
			b.WriteByte(s[i])
		case ' ', '\t', '\n', '\r', ',':
			if depth > 0 {
				continue
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}

func normalizedFuncName(s string) string {
	s = strings.ReplaceAll(s, "-fm", "$bound")
	s = strings.ReplaceAll(s, "go.shape.", "")
	s = strings.ReplaceAll(s, "interface {}", "interface{}")
	s = strings.ReplaceAll(s, "interface{}", "any")
	return normalizeBracketContent(s)
}

func canonicalFuncName(s string) string {
	return stripBracketContent(normalizedFuncName(s))
}
