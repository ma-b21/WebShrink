// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package whitelist handles compiler-side instrumentation that cooperates
// with the custom runtime whitelist stack. It is responsible for finding
// functions that require PushWhitelist/PopWhitelist calls and injecting the
// corresponding IR nodes before the back end runs.
package whitelist

import (
	"go/constant"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"log"
	"strconv"
	"strings"
)

// Apply scans all functions in the current compilation unit and injects
// whitelist prologues for those listed in the configuration. It is a no-op
// if no whitelist configuration is available.
func Apply() {
	cfg := base.Flag.Cfg.Whitelist
	if cfg == nil {
		return
	}
	if len(cfg.FunctionIDs) == 0 && len(cfg.Locations) == 0 {
		return
	}
	// Never instrument runtime-related packages. These packages may execute on
	// the system stack, and the current whitelist strategy relies on defer,
	// which is illegal on that stack.
	if base.Flag.CompilingRuntime || base.Ctxt.Pkgpath == "runtime" {
		return
	}

	var parsedSigs []parsedSignature
	if len(cfg.Signatures) > 0 {
		for i, sigSpec := range cfg.Signatures {
			parsedSig, err := getParsedSignature("__whitelist_global__"+strconv.Itoa(i), sigSpec)
			if err != nil {
				if shouldIgnoreSignatureParseError(err) {
					// This package may not import the types referenced by the signature,
					// or the signature itself may be malformed. In either case, no
					// function in this package can match this signature.
					if whitelistVerboseEnabled() {
						log.Printf("whitelist: signature parsing failed (ignored): %v", err)
					}
					continue
				}
				base.Fatalf("whitelist: %v", err)
			}
			parsedSigs = append(parsedSigs, *parsedSig)
		}
	}
	if len(parsedSigs) == 0 {
		return
	}

	pushFn := typecheck.LookupRuntime("PushWhitelist")
	popFn := typecheck.LookupRuntime("PopWhitelist")

	for _, fn := range typecheck.Target.Funcs {
		if fn == nil {
			continue
		}
		applyFunc(fn, cfg, parsedSigs, pushFn, popFn)
	}
}

func applyFunc(fn *ir.Func, cfg *base.WhitelistConfig, parsedSigs []parsedSignature, pushFn, popFn *ir.Name) {
	name := runtimeFuncName(fn)
	if name == "" {
		return
	}
	if shouldSkipWhitelistInjection(fn) {
		if whitelistVerboseEnabled() {
			log.Printf("whitelist: skip fn=%s due to unsafe pragma/runtime context", name)
		}
		return
	}
	// Skip functions without a body (external function declarations).
	// These are typically implemented in assembly or provided by the runtime.
	if len(fn.Body) == 0 {
		return
	}

	if !matchesAnySignature(fn, parsedSigs) {
		return
	}

	var id uint32
	var ok bool

	log.Printf("whitelist: checking fn=%s", name)

	// 1. Try matching by function name
	if len(cfg.FunctionIDs) > 0 {
		id, ok = cfg.FunctionIDs[name]
		if ok {
			log.Printf("whitelist: match name %s -> id=%d", name, id)
		}
	}

	// 2. If not matched by name, try matching by location
	if !ok && len(cfg.Locations) > 0 {
		pos := base.Ctxt.PosTable.Pos(fn.Pos())
		file := pos.Filename()
		line := pos.Line()
		col := pos.Col()
		log.Printf("applyFunc: file=%s line=%d col=%d", file, line, col)

		for _, loc := range cfg.Locations {
			// Match file suffix to handle absolute/relative path differences
			if strings.HasSuffix(file, loc.File) && line == uint(loc.Line) {
				// If column is specified in config (non-zero), it must match
				if loc.Col != 0 && col != uint(loc.Col) {
					continue
				}
				id = loc.ID
				ok = true
				if whitelistVerboseEnabled() {
					log.Printf("whitelist: match location file=%s line=%d col=%d -> id=%d", file, line, col, id)
				}
				break
			}
		}
	}

	if !ok {
		return
	}
	log.Printf("Injecting whitelist prologue for fn=%s id=%d", name, id)
	injectWhitelistPrologue(fn, id, pushFn, popFn)
}

func shouldSkipWhitelistInjection(fn *ir.Func) bool {
	if fn == nil {
		return true
	}
	if base.Flag.CompilingRuntime {
		return true
	}
	return fn.Pragma&(ir.Nosplit|ir.Systemstack) != 0
}

func whitelistVerboseEnabled() bool {
	return base.Flag.LowerV != nil && *base.Flag.LowerV
}

func matchesSignature(fn *ir.Func, parsed parsedSignature) bool {
	ft := fn.Type()
	if ft == nil {
		return false
	}
	if len(parsed.params) != ft.NumParams() || len(parsed.results) != ft.NumResults() {
		return false
	}
	for i, want := range parsed.params {
		if i < len(parsed.paramsAny) && parsed.paramsAny[i] {
			continue
		}
		if !types.Identical(ft.Param(i).Type, want) {
			return false
		}
	}
	for i, want := range parsed.results {
		if i < len(parsed.resultsAny) && parsed.resultsAny[i] {
			continue
		}
		if !types.Identical(ft.Result(i).Type, want) {
			return false
		}
	}
	return true
}

func matchesAnySignature(fn *ir.Func, parsedSigs []parsedSignature) bool {
	for _, sig := range parsedSigs {
		if matchesSignature(fn, sig) {
			return true
		}
	}
	return false
}

// runtimeFuncName constructs the same fully qualified name format that the
// runtime produces via runtime.FuncForPC().Name().
func runtimeFuncName(fn *ir.Func) string {
	if fn == nil || fn.Nname == nil {
		return ""
	}
	sym := fn.Sym()
	if sym == nil {
		return ""
	}
	pkgPath := ""
	if sym.Pkg != nil {
		pkgPath = sym.Pkg.Path
	}
	if pkgPath == "" {
		pkgPath = base.Ctxt.Pkgpath
	}
	if pkgPath == "" {
		return sym.Name
	}
	return pkgPath + "." + sym.Name
}

func injectWhitelistPrologue(fn *ir.Func, id uint32, pushFn, popFn *ir.Name) {
	ir.WithFunc(fn, func() {
		pos := fn.Pos()

		var stmts []ir.Node

		if base.Flag.WhitelistPrintPos {
			srcPos := base.Ctxt.PosTable.Pos(pos)
			loc := srcPos.Filename() + ":" + strconv.Itoa(int(srcPos.Line())) + " id=" + strconv.FormatUint(uint64(id), 10) + "\n"
			msg := ir.NewBasicLit(pos, types.Types[types.TSTRING], constant.MakeString(loc))

			printLockCall := typecheck.Call(pos, typecheck.LookupRuntime("printlock"), nil, false)
			printStringCall := typecheck.Call(pos, typecheck.LookupRuntime("printstring"), []ir.Node{msg}, false)
			printUnlockCall := typecheck.Call(pos, typecheck.LookupRuntime("printunlock"), nil, false)
			stmts = append(stmts, typecheck.Stmt(printLockCall), typecheck.Stmt(printStringCall), typecheck.Stmt(printUnlockCall))
		}

		idArg := ir.NewInt(pos, int64(id))
		pushCall := typecheck.Call(pos, pushFn, []ir.Node{idArg}, false)

		popCall := typecheck.Call(pos, popFn, nil, false)
		deferNode := ir.NewGoDeferStmt(pos, ir.ODEFER, popCall)

		stmts = append(stmts, typecheck.Stmt(pushCall), typecheck.Stmt(deferNode))
		fn.Body.Prepend(stmts...)
		fn.SetHasDefer(true)
	})
}

func shouldIgnoreSignatureParseError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unknown package") ||
		strings.Contains(msg, "unknown type") ||
		strings.Contains(msg, "invalid type expression") ||
		strings.Contains(msg, "failed to parse type expression") ||
		strings.Contains(msg, "empty type expression")
}
