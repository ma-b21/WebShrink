package builder

import (
	"go/types"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

// ImportedGraphNeedsMetadata reports whether an imported callgraph still uses the
// legacy schema that lacks per-edge VTA metadata and per-node SSA position info.
func ImportedGraphNeedsMetadata(unified *UnifiedCallGraph) bool {
	if unified == nil {
		return false
	}
	for _, node := range unified.Nodes {
		if node == nil {
			continue
		}
		if node.HasSSA || node.Pos != "" {
			return false
		}
		for _, edge := range node.Out {
			if edge != nil && edge.VTA != nil {
				return false
			}
		}
	}
	return true
}

// EnrichImportedGraphMetadata retrofits legacy callgraph.json imports with enough
// SSA-derived metadata for later stages to distinguish interface / function-value
// edges when rebuilding DAGs.
func EnrichImportedGraphMetadata(loadPath string, unified *UnifiedCallGraph) error {
	if unified == nil {
		return nil
	}

	loadPath = normalizeLoadPath(loadPath)
	prog := loadPathToProg[loadPath]
	pkgs := loadPathToPkgs[loadPath]
	if prog == nil || len(pkgs) == 0 {
		loadedPkgs, loadedProg, ssaPkgs := loadPackagesAndSSA(loadPath)
		registerLoadedProgram(loadPath, loadedPkgs, loadedProg, ssaPkgs, nil)
		prog = loadedProg
	}
	if prog == nil {
		return nil
	}

	nameToFn := make(map[string]*ssa.Function)
	var funcsBySig typeutil.Map
	methodsByID := make(map[string][]*ssa.Function)
	for fn := range ssautil.AllFunctions(prog) {
		if fn == nil {
			continue
		}
		nameToFn[fn.String()] = fn
		if fn.Signature == nil {
			continue
		}
		if fn.Signature.Recv() == nil {
			funcs, _ := funcsBySig.At(fn.Signature).([]*ssa.Function)
			funcs = append(funcs, fn)
			funcsBySig.Set(fn.Signature, funcs)
			continue
		}
		if obj := fn.Object(); obj != nil {
			method, ok := obj.(*types.Func)
			if ok {
				methodsByID[method.Id()] = append(methodsByID[method.Id()], fn)
			}
		}
	}

	for _, node := range unified.Nodes {
		if node == nil {
			continue
		}
		fn := nameToFn[node.Key]
		if fn == nil {
			continue
		}
		node.HasSSA = true
		if pos := fn.Prog.Fset.Position(fn.Pos()); pos.IsValid() {
			node.Pos = pos.String()
		}

		edgesByCallee := collectCallerEdgeMetadata(fn, funcsBySig, methodsByID)
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil {
				continue
			}
			infos := edgesByCallee[edge.Callee.Key]
			if len(infos) == 0 {
				continue
			}
			info := infos[0]
			edgesByCallee[edge.Callee.Key] = infos[1:]
			edge.VTA = cloneVTAEdgeInfo(&info)
			if edge.Source == "" || edge.Source == "import" {
				edge.Source = "vta"
			}
		}
	}

	return nil
}

func collectCallerEdgeMetadata(
	fn *ssa.Function,
	funcsBySig typeutil.Map,
	methodsByID map[string][]*ssa.Function,
) map[string][]VTAEdgeInfo {
	edges := make(map[string][]VTAEdgeInfo)
	if fn == nil {
		return edges
	}

	lookupMethods := func(iface *types.Interface, m *types.Func) []*ssa.Function {
		if iface == nil || m == nil {
			return nil
		}
		var methods []*ssa.Function
		for _, f := range methodsByID[m.Id()] {
			if f == nil || f.Signature == nil {
				continue
			}
			recv := f.Signature.Recv()
			if recv == nil {
				continue
			}
			if types.Implements(recv.Type(), iface) {
				methods = append(methods, f)
			}
		}
		return methods
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			common := call.Common()
			if common == nil {
				continue
			}

			var (
				callees       []*ssa.Function
				isInvoke      bool
				isDynamicFunc bool
			)
			switch {
			case common.IsInvoke():
				iface, ok := common.Value.Type().Underlying().(*types.Interface)
				if !ok {
					continue
				}
				callees = lookupMethods(iface, common.Method)
				isInvoke = true
			case common.StaticCallee() != nil:
				callees = []*ssa.Function{common.StaticCallee()}
			default:
				if _, ok := common.Value.(*ssa.Builtin); ok {
					continue
				}
				callees, _ = funcsBySig.At(common.Signature()).([]*ssa.Function)
				isDynamicFunc = true
			}

			pos := fn.Prog.Fset.Position(call.Pos())
			info := VTAEdgeInfo{
				HasSite: pos.IsValid(),
			}
			fillVTAEdgeInfo(&info, common, fn, call.Pos())
			info.IsInvoke = isInvoke
			info.IsDynamicFunc = isDynamicFunc
			for _, callee := range callees {
				if callee == nil {
					continue
				}
				edges[callee.String()] = append(edges[callee.String()], info)
			}
		}
	}

	return edges
}
