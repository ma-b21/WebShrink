// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package whitelist

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"cmd/compile/internal/base"
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// parsedSignature caches the fully resolved parameter and result types for a
// signature specification.
type parsedSignature struct {
	params     []*types.Type
	results    []*types.Type
	paramsAny  []bool
	resultsAny []bool
}

var signatureCache sync.Map // map[string]*parsedSignature

func getParsedSignature(name string, spec base.WhitelistSignature) (*parsedSignature, error) {
	if cached, ok := signatureCache.Load(name); ok {
		return cached.(*parsedSignature), nil
	}
	parsed, err := parseSignatureSpec(spec)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	signatureCache.Store(name, parsed)
	return parsed, nil
}

func parseSignatureSpec(spec base.WhitelistSignature) (*parsedSignature, error) {
	parsed := &parsedSignature{
		params:     make([]*types.Type, 0, len(spec.Params)),
		results:    make([]*types.Type, 0, len(spec.Results)),
		paramsAny:  make([]bool, 0, len(spec.Params)),
		resultsAny: make([]bool, 0, len(spec.Results)),
	}
	for i, raw := range spec.Params {
		if strings.EqualFold(strings.TrimSpace(raw), "any") {
			parsed.params = append(parsed.params, nil)
			parsed.paramsAny = append(parsed.paramsAny, true)
			continue
		}
		t, err := parseTypeLiteral(raw)
		if err != nil {
			return nil, fmt.Errorf("parameter %d: %w", i, err)
		}
		parsed.params = append(parsed.params, t)
		parsed.paramsAny = append(parsed.paramsAny, false)
	}
	for i, raw := range spec.Results {
		if strings.EqualFold(strings.TrimSpace(raw), "any") {
			parsed.results = append(parsed.results, nil)
			parsed.resultsAny = append(parsed.resultsAny, true)
			continue
		}
		t, err := parseTypeLiteral(raw)
		if err != nil {
			return nil, fmt.Errorf("result %d: %w", i, err)
		}
		parsed.results = append(parsed.results, t)
		parsed.resultsAny = append(parsed.resultsAny, false)
	}
	return parsed, nil
}

const (
	parserPackageName = "__whitelist_parser"
	parserVarName     = "__whitelist_type_expr"
	parserFileName    = "whitelist_type_expr.go"
	aliasPrefix       = "__whitelist_pkg"
)

func parseTypeLiteral(raw string) (*types.Type, error) {
	expr := strings.TrimSpace(raw)
	if expr == "" {
		return nil, fmt.Errorf("empty type expression")
	}
	rewritten, aliasMap := rewriteForParser(expr)
	syntaxExpr, err := parseTypeExpr(rewritten, aliasMap)
	if err != nil {
		return nil, err
	}
	return (typeResolver{aliasToPath: aliasMap}).resolve(syntaxExpr)
}

func parseTypeExpr(expr string, aliasMap map[string]string) (syntax.Expr, error) {
	var importSection strings.Builder
	if len(aliasMap) != 0 {
		aliases := make([]string, 0, len(aliasMap))
		for alias := range aliasMap {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		importSection.WriteString("import (\n")
		for _, alias := range aliases {
			fmt.Fprintf(&importSection, "\t%s %q\n", alias, aliasMap[alias])
		}
		importSection.WriteString(")\n")
	}
	src := fmt.Sprintf("package %s\n%svar %s %s\n", parserPackageName, importSection.String(), parserVarName, expr)
	base := syntax.NewFileBase(parserFileName)
	var parseErr error
	file, err := syntax.Parse(base, strings.NewReader(src), func(err error) {
		if parseErr == nil {
			parseErr = err
		}
	}, nil, 0)
	if err != nil {
		parseErr = err
	}
	if parseErr != nil {
		return nil, fmt.Errorf("invalid type expression: %s", parseErr.Error())
	}
	if file == nil {
		return nil, fmt.Errorf("failed to parse type expression")
	}
	for _, decl := range file.DeclList {
		v, ok := decl.(*syntax.VarDecl)
		if !ok {
			continue
		}
		for _, name := range v.NameList {
			if name.Value == parserVarName {
				if v.Type == nil {
					return nil, fmt.Errorf("missing parsed type expression")
				}
				return v.Type, nil
			}
		}
	}
	return nil, fmt.Errorf("parsed expression sentinel not found")
}

type typeResolver struct {
	aliasToPath map[string]string
}

func (tr typeResolver) resolve(expr syntax.Expr) (*types.Type, error) {
	switch node := expr.(type) {
	case *syntax.Name:
		return lookupTypeInPackage("", normalizeIdentifier(node.Value))
	case *syntax.SelectorExpr:
		return tr.resolveSelector(node)
	case *syntax.ArrayType:
		if node.Len == nil {
			elem, err := tr.resolve(node.Elem)
			if err != nil {
				return nil, err
			}
			return types.NewSlice(elem), nil
		}
		bound, err := arrayBound(node.Len)
		if err != nil {
			return nil, err
		}
		elem, err := tr.resolve(node.Elem)
		if err != nil {
			return nil, err
		}
		return types.NewArray(elem, bound), nil
	case *syntax.SliceType:
		elem, err := tr.resolve(node.Elem)
		if err != nil {
			return nil, err
		}
		return types.NewSlice(elem), nil
	case *syntax.MapType:
		key, err := tr.resolve(node.Key)
		if err != nil {
			return nil, err
		}
		val, err := tr.resolve(node.Value)
		if err != nil {
			return nil, err
		}
		return types.NewMap(key, val), nil
	case *syntax.ChanType:
		elem, err := tr.resolve(node.Elem)
		if err != nil {
			return nil, err
		}
		return types.NewChan(elem, channelDir(node.Dir)), nil
	case *syntax.Operation:
		if node.Op != syntax.Mul || node.Y != nil {
			return nil, fmt.Errorf("unsupported operation in type expression")
		}
		elem, err := tr.resolve(node.X)
		if err != nil {
			return nil, err
		}
		return types.NewPtr(elem), nil
	case *syntax.FuncType:
		return tr.resolveFuncType(node)
	case *syntax.ParenExpr:
		return tr.resolve(node.X)
	default:
		return nil, fmt.Errorf("unsupported type expression %T", node)
	}
}

func (tr typeResolver) resolveSelector(sel *syntax.SelectorExpr) (*types.Type, error) {
	pkgPath, err := tr.packagePathFromExpr(sel.X)
	if err != nil {
		return nil, err
	}
	return lookupTypeInPackage(pkgPath, sel.Sel.Value)
}

func (tr typeResolver) packagePathFromExpr(expr syntax.Expr) (string, error) {
	var parts []string
	for {
		switch node := expr.(type) {
		case *syntax.Name:
			parts = append(parts, normalizeIdentifier(node.Value))
			for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
				parts[i], parts[j] = parts[j], parts[i]
			}
			path := strings.Join(parts, ".")
			if actual, ok := tr.aliasToPath[path]; ok {
				return actual, nil
			}
			return path, nil
		case *syntax.SelectorExpr:
			parts = append(parts, normalizeIdentifier(node.Sel.Value))
			expr = node.X
		default:
			return "", fmt.Errorf("invalid package path expression: %T", expr)
		}
	}
}

func (tr typeResolver) resolveFuncType(ft *syntax.FuncType) (*types.Type, error) {
	params, variadic, err := tr.convertParamFields(ft.ParamList)
	if err != nil {
		return nil, err
	}
	results, err := tr.convertResultFields(ft.ResultList)
	if err != nil {
		return nil, err
	}
	sig := types.NewSignature(nil, params, results)
	if variadic && len(params) != 0 {
		params[len(params)-1].SetIsDDD(true)
	}
	return sig, nil
}

func (tr typeResolver) convertParamFields(fields []*syntax.Field) ([]*types.Field, bool, error) {
	if len(fields) == 0 {
		return nil, false, nil
	}
	result := make([]*types.Field, 0, len(fields))
	variadic := false
	for i, field := range fields {
		if field == nil || field.Type == nil {
			continue
		}
		typExpr := field.Type
		isVariadic := false
		if dots, ok := typExpr.(*syntax.DotsType); ok {
			isVariadic = true
			typExpr = dots.Elem
		}
		typ, err := tr.resolve(typExpr)
		if err != nil {
			return nil, false, err
		}
		if isVariadic {
			if variadic {
				return nil, false, fmt.Errorf("multiple variadic parameters")
			}
			if i != len(fields)-1 {
				return nil, false, fmt.Errorf("variadic parameter must be last")
			}
			variadic = true
		}
		result = append(result, types.NewField(src.NoXPos, nil, typ))
	}
	return result, variadic, nil
}

func (tr typeResolver) convertResultFields(fields []*syntax.Field) ([]*types.Field, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	result := make([]*types.Field, 0, len(fields))
	for _, field := range fields {
		if field == nil || field.Type == nil {
			continue
		}
		typ, err := tr.resolve(field.Type)
		if err != nil {
			return nil, err
		}
		result = append(result, types.NewField(src.NoXPos, nil, typ))
	}
	return result, nil
}

func arrayBound(expr syntax.Expr) (int64, error) {
	lit, ok := expr.(*syntax.BasicLit)
	if !ok || lit.Kind != syntax.IntLit || lit.Bad {
		return 0, fmt.Errorf("array bound must be an integer literal")
	}
	b, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid array bound: %w", err)
	}
	return b, nil
}

func channelDir(dir syntax.ChanDir) types.ChanDir {
	switch dir {
	case syntax.SendOnly:
		return types.Csend
	case syntax.RecvOnly:
		return types.Crecv
	default:
		return types.Cboth
	}
}

func normalizeIdentifier(name string) string {
	return strings.TrimSpace(name)
}

func rewriteForParser(expr string) (string, map[string]string) {
	aliasToPath := make(map[string]string)
	pathToAlias := make(map[string]string)
	var b strings.Builder
	for i := 0; i < len(expr); {
		ch := expr[i]
		if isNameStart(ch) {
			start := i
			i++
			for i < len(expr) && isNamePart(expr[i]) {
				i++
			}
			token := expr[start:i]
			if replacement, ok := rewriteToken(token, aliasToPath, pathToAlias); ok {
				b.WriteString(replacement)
				continue
			}
			b.WriteString(token)
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return b.String(), aliasToPath
}

func rewriteToken(token string, aliasToPath, pathToAlias map[string]string) (string, bool) {
	idx := strings.LastIndex(token, ".")
	if idx <= 0 || idx == len(token)-1 {
		return "", false
	}
	pkgPath := token[:idx]
	typeName := token[idx+1:]
	if !isIdentifier(typeName) {
		return "", false
	}
	alias, ok := pathToAlias[pkgPath]
	if !ok {
		alias = fmt.Sprintf("%s%d", aliasPrefix, len(pathToAlias))
		pathToAlias[pkgPath] = alias
		aliasToPath[alias] = pkgPath
	}
	return alias + "." + typeName, true
}

func isNameStart(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

func isNamePart(b byte) bool {
	return isNameStart(b) || ('0' <= b && b <= '9') || b == '_' || b == '/' || b == '.' || b == '-'
}

func isIdentifier(s string) bool {
	if s == "" || !isNameStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if !isNameStart(b) && !('0' <= b && b <= '9') {
			return false
		}
	}
	return true
}

var builtinTypeGetters = map[string]func() *types.Type{
	"bool":       func() *types.Type { return types.Types[types.TBOOL] },
	"byte":       func() *types.Type { return types.ByteType },
	"complex64":  func() *types.Type { return types.Types[types.TCOMPLEX64] },
	"complex128": func() *types.Type { return types.Types[types.TCOMPLEX128] },
	"error":      func() *types.Type { return types.ErrorType },
	"float32":    func() *types.Type { return types.Types[types.TFLOAT32] },
	"float64":    func() *types.Type { return types.Types[types.TFLOAT64] },
	"int":        func() *types.Type { return types.Types[types.TINT] },
	"int8":       func() *types.Type { return types.Types[types.TINT8] },
	"int16":      func() *types.Type { return types.Types[types.TINT16] },
	"int32":      func() *types.Type { return types.Types[types.TINT32] },
	"int64":      func() *types.Type { return types.Types[types.TINT64] },
	"rune":       func() *types.Type { return types.RuneType },
	"string":     func() *types.Type { return types.Types[types.TSTRING] },
	"uint":       func() *types.Type { return types.Types[types.TUINT] },
	"uint8":      func() *types.Type { return types.Types[types.TUINT8] },
	"uint16":     func() *types.Type { return types.Types[types.TUINT16] },
	"uint32":     func() *types.Type { return types.Types[types.TUINT32] },
	"uint64":     func() *types.Type { return types.Types[types.TUINT64] },
	"uintptr":    func() *types.Type { return types.Types[types.TUINTPTR] },
	"any":        func() *types.Type { return types.AnyType },
}

func lookupBuiltinType(name string) *types.Type {
	if getter, ok := builtinTypeGetters[name]; ok {
		return getter()
	}
	return nil
}

func lookupTypeInPackage(pkgPath, name string) (*types.Type, error) {
	pkgPath = strings.TrimSpace(pkgPath)
	name = strings.TrimSpace(name)
	if pkgPath == "" {
		if t := lookupBuiltinType(name); t != nil {
			return t, nil
		}
		if types.LocalPkg != nil {
			if sym := types.LocalPkg.Syms[name]; sym != nil && sym.Def != nil {
				return sym.Def.Type(), nil
			}
		}
		// Search any package with matching name for convenience (e.g., dot imports are not supported).
		for _, pkg := range types.PkgMap() {
			if sym := pkg.Syms[name]; sym != nil && sym.Def != nil {
				return sym.Def.Type(), nil
			}
		}
		return nil, fmt.Errorf("unknown type %q", name)
	}
	pkg := types.PkgMap()[pkgPath]
	if pkg == nil {
		return nil, fmt.Errorf("unknown package %q", pkgPath)
	}
	if sym := pkg.Syms[name]; sym != nil && sym.Def != nil {
		return sym.Def.Type(), nil
	}
	return nil, fmt.Errorf("unknown type %q in package %q", name, pkgPath)
}
