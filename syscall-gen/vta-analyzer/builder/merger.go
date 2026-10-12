package builder

import (
	asm "asm-analyzer/types"
	"log"
	"strconv"
	"strings"

	"golang.org/x/tools/go/callgraph"
	linktypes "linkname-analyzer/types"
)

func AddVtaGraph(vtaGraph *CallGraph, unified *UnifiedCallGraph) bool {
	// 先确保所有节点存在，再统一补齐边，避免 merge 顺序影响边完整性。
	changed := false

	for key, vtaNode := range vtaGraph.Nodes {
		node, added := unified.AddOrGetNode(vtaNode, nil, "")
		if added {
			changed = true
		}

		// 添加系统调用信息
		if syscalls, exists := vtaGraph.Syscalls[key]; exists {
			for _, syscall := range syscalls {
				syscall_num, err := strconv.Atoi(syscall)
				if err != nil {
					log.Println("Error trans", syscall, "to int")
					continue
				}
				node.Syscalls = append(node.Syscalls, syscall_num)
				node.SyscallBitSet.Set(uint(syscall_num))
			}
		}
	}

	// 添加 VTA 边
	for _, vtaNode := range vtaGraph.Nodes {
		if vtaNode == nil || vtaNode.Func == nil {
			continue
		}
		callerNode := unified.Nodes[vtaNode.Func.String()]
		if callerNode == nil {
			continue
		}
		for _, vtaEdge := range vtaNode.Out {
			if vtaEdge.Callee == nil || vtaEdge.Callee.Func == nil {
				continue
			}

			calleeNode := unified.Nodes[vtaEdge.Callee.Func.String()]

			if calleeNode != nil && !hasEquivalentUnifiedEdge(callerNode, calleeNode, "vta", vtaEdge) {
				unified.AddEdge(callerNode, calleeNode, vtaEdge, "vta")
				changed = true
			}
		}
	}

	return changed
}

// MergeCallGraphs 合并 VTA 调用图和汇编调用图
func MergeCallGraphs(unified *UnifiedCallGraph, vtaGraph *CallGraph, asmFuncs map[string]*asm.AsmFunction, declImplMap map[string]linktypes.ImplInfo) *UnifiedCallGraph {
	if unified == nil {
		unified = NewUnifiedCallGraph()
	}
	if vtaGraph != nil {
		AddVtaGraph(vtaGraph, unified)
	}

	// 从汇编函数补充/更新节点
	if asmFuncs != nil {
		need_Update := true
		for need_Update {
			need_Update = false
			leaves := unified.FindLeafNodes()
			for _, leaf := range leaves {
				if asmFunc, exists := asmFuncs[leaf.Key]; exists {
					node, _ := unified.AddOrGetNode(nil, asmFunc, "")
					node.Asm = asmFunc

					// 如果节点只有 Asm 没有 SSA，标记为纯汇编
					if !node.HasSSA {
						node.IsAsm = true
					}

					// 添加汇编的系统调用信息
					if len(asmFunc.Syscalls) > 0 {
						for _, syscall := range asmFunc.Syscalls {
							syscall_num, err := strconv.Atoi(syscall)
							if err != nil {
								log.Println("Error trans", syscall, "to int")
								continue
							}
							node.Syscalls = append(node.Syscalls, syscall_num)
							node.SyscallBitSet.Set(uint(syscall_num))
						}
					}

					callerNode := unified.Nodes[asmFunc.FuncName]
					if callerNode == nil {
						continue
					}

					for _, calleeName := range asmFunc.Callees {
						pkg := rsplitN(calleeName, ".", 1)[0]
						var cg *CallGraph
						if pkg == "builtins" {
							cg = BuildSubgraph(GetBuiltinSubGraphNode(rsplitN(calleeName, ".", 1)[1]))
						} else {
							cg = GetLinkNameExtendedVtaGraph(pkg, calleeName, declImplMap)
						}
						if cg == nil {
							calleeNode, added := unified.AddOrGetNode(nil, nil, calleeName)
							if added {
								need_Update = true
							}
							if calleeFunc, ok := asmFuncs[calleeName]; ok {
								calleeNode.Asm = calleeFunc
								calleeNode.IsAsm = true
							}
							unified.AddEdge(callerNode, calleeNode, nil, "asm")
							continue
						}
						need_Update = true
						AddVtaGraph(cg, unified)
						unified.AddEdge(callerNode, unified.Nodes[calleeName], nil, "asm")
					}
				}
			}
		}
	}

	// 汇总系统调用
	for key, node := range unified.Nodes {
		if len(node.Syscalls) > 0 {
			unified.Syscalls[key] = node.Syscalls
		}
	}

	return unified
}

func rsplitN(s, sep string, n int) []string {
	if n <= 0 {
		// n <= 0 表示无限次
		return strings.Split(s, sep)
	}
	if sep == "" {
		// 空分隔符，按 rune 分割
		runes := []rune(s)
		if n > len(runes) {
			n = len(runes)
		}
		parts := []string{}
		for i := len(runes) - n; i < len(runes); i++ {
			parts = append(parts, string(runes[i]))
		}
		return append([]string{string(runes[:len(runes)-len(parts)])}, parts...)
	}

	parts := make([]string, 0, n+1)
	remainder := s
	for i := 0; i < n; i++ {
		idx := strings.LastIndex(remainder, sep)
		if idx == -1 {
			break
		}
		parts = append([]string{remainder[idx+len(sep):]}, parts...)
		remainder = remainder[:idx]
	}
	return append([]string{remainder}, parts...)
}

var syscallFuncs = []string{
	"syscall.Syscall",
	"syscall.RawSyscall",
	"syscall.rawSyscallNoError",
	"syscall.RawSyscall6",
	"syscall.rawVforkSyscall",
	"internal/runtime/syscall.Syscall6",
	"syscall.Syscall6",
	"golang.org/x/sys/unix.Syscall",
	"golang.org/x/sys/unix.Syscall6",
	"golang.org/x/sys/unix.RawSyscall",
	"golang.org/x/sys/unix.RawSyscall6",
}
var asmCallFuncs = []string{
	"runtime.systemstack",
	"runtime.mcall",
}

// 增加mcall和systemstack调用
func AddRegisterCall(unifiedCG *UnifiedCallGraph, declImplMap map[string]linktypes.ImplInfo) {
	need_update := true
	for need_update {
		need_update = addAsmRegisterCall(unifiedCG, declImplMap)
	}
	addDynamicWrapperCall(unifiedCG)
}

func addAsmRegisterCall(unifiedCG *UnifiedCallGraph, declImplMap map[string]linktypes.ImplInfo) bool {
	updated := false
	for _, funcName := range asmCallFuncs {
		node := unifiedCG.Nodes[funcName]
		if node == nil {
			continue
		}
		for _, edge := range node.In {
			if edge.VTA == nil || !edge.VTA.HasSite {
				log.Printf("warn: %s 被非Go代码调用; skip register-param recovery\n", funcName)
				continue
			}

			targetFunc, ok := resolveRuntimeWrapperTarget(edge.VTA.Arg0)
			if !ok {
				log.Fatal("无法解析 runtime 包装函数参数", edge.VTA.Arg0)
			}

			targetVta := GetLinkNameExtendedVtaGraph("runtime", targetFunc, declImplMap)
			if targetVta == nil {
				log.Fatalf("有个调用图没找到: wrapper=%s arg=%s target=%s", funcName, edge.VTA.Arg0, targetFunc)
			}
			if AddVtaGraph(targetVta, unifiedCG) {
				updated = true
			}

			targetNode := unifiedCG.Nodes[targetFunc]
			if targetNode == nil || hasRetainedUnifiedEdge(edge.Caller, targetNode) {
				continue
			}
			unifiedCG.AddEdge(edge.Caller, targetNode, nil, "Register Param")
			updated = true
		}
	}
	return updated
}

// addDynamicWrapperCall restores caller-to-target edges for helper functions
// such as os.ignoringEINTR(fn), where the real call target is hidden behind a
// dynamic function-value invocation that would otherwise be dropped by BuildDAG.
func addDynamicWrapperCall(unifiedCG *UnifiedCallGraph) bool {
	updated := false
	for _, wrapper := range unifiedCG.Nodes {
		if wrapper == nil {
			continue
		}

		candidates := dynamicWrapperTargets(wrapper)

		for _, edge := range wrapper.In {
			if edge == nil || edge.Caller == nil || edge.VTA == nil || !edge.VTA.HasSite {
				continue
			}

			targetNode := resolveDynamicWrapperTarget(edge.Caller.Key, edge.VTA.Arg0, candidates)
			if targetNode == nil {
				targetNode = resolveDynamicWrapperTargetGlobal(edge.Caller, edge.VTA.Arg0, unifiedCG)
			}
			if targetNode == nil || hasRetainedUnifiedEdge(edge.Caller, targetNode) {
				continue
			}

			unifiedCG.AddEdge(edge.Caller, targetNode, nil, "Register Param")
			updated = true
		}
	}
	return updated
}

var wrapperDynamicHelpers = map[string][]string{
	"(*sync.Once).Do": {"(*sync.Once).doSlow"},
}

func AddSyscallNum(unifiedCG *UnifiedCallGraph) {
	for _, funcName := range syscallFuncs {
		Node := unifiedCG.Nodes[funcName]
		if Node == nil {
			continue
		}
		for _, edge := range Node.In {
			if edge.VTA == nil || !edge.VTA.HasSite {
				log.Printf("warn: syscall helper %s 被非Go代码调用; skip syscall-num recovery\n", funcName)
				continue
			} else {
				arg := edge.VTA.Arg0
				if strings.HasPrefix(arg, "parameter trap") { // trap 参数传递，可忽略，在上层已分析
					continue
				} else if arg == "*fcntl64Syscall" {
					edge.Caller.Syscalls = append(edge.Caller.Syscalls, 72) // SYS_FCNTL
					edge.Caller.SyscallBitSet.Set(72)
				} else if strings.HasSuffix(arg, ":uintptr") { // 常量参数
					syscall_num, err := strconv.Atoi(strings.Split(arg, ":")[0])
					if err != nil {
						log.Println("Error trans", strings.Split(arg, ":")[0], "to int")
						continue
					}
					edge.Caller.Syscalls = append(edge.Caller.Syscalls, syscall_num)
					edge.Caller.SyscallBitSet.Set(uint(syscall_num))
				} else {
					log.Fatal("未见的参数类型", arg)
				}
			}
		}

	}
}

func resolveRuntimeWrapperTarget(arg string) (string, bool) {
	rawTarget, ok := parseWrappedFuncArg(arg)
	if !ok {
		return "", false
	}
	if rawTarget == "" {
		return "", false
	}

	if strings.HasPrefix(rawTarget, "runtime.") || strings.Contains(rawTarget, "/") {
		return rawTarget, true
	}
	if rawTarget[0] != '(' {
		return "runtime." + rawTarget, true
	}
	if strings.Contains(rawTarget, "runtime.") {
		return rawTarget, true
	}
	if rawTarget[1] == '*' {
		return "(*runtime." + strings.Split(rawTarget, "*")[1], true
	}
	return "(runtime." + strings.TrimLeft(rawTarget, "("), true
}

func parseWrappedFuncArg(arg string) (string, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", false
	}
	if strings.HasPrefix(arg, "make closure") {
		fields := strings.Fields(arg)
		if len(fields) < 3 {
			return "", false
		}
		return fields[2], true
	}
	if strings.Contains(arg, " ") {
		return "", false
	}
	return arg, true
}

func dynamicWrapperTargets(wrapper *UnifiedNode) []*UnifiedNode {
	seen := make(map[string]bool)
	var targets []*UnifiedNode

	addTargets := func(node *UnifiedNode) {
		if node == nil {
			return
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Callee == nil || edge.VTA == nil || !edge.VTA.IsDynamicFunc {
				continue
			}
			if seen[edge.Callee.Key] {
				continue
			}
			seen[edge.Callee.Key] = true
			targets = append(targets, edge.Callee)
		}
	}

	addTargets(wrapper)
	for _, helperKey := range wrapperDynamicHelpers[wrapper.Key] {
		addTargets(findWrapperCallee(wrapper, helperKey))
	}

	return targets
}

func findWrapperCallee(wrapper *UnifiedNode, calleeKey string) *UnifiedNode {
	if wrapper == nil || calleeKey == "" {
		return nil
	}
	for _, edge := range wrapper.Out {
		if edge != nil && edge.Callee != nil && edge.Callee.Key == calleeKey {
			return edge.Callee
		}
	}
	return nil
}

func resolveDynamicWrapperTarget(callerKey string, arg string, candidates []*UnifiedNode) *UnifiedNode {
	rawTarget, ok := parseWrappedFuncArg(arg)
	if !ok {
		return nil
	}

	bestScore := 0
	var best *UnifiedNode
	ambiguous := false

	for _, candidate := range candidates {
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

func resolveDynamicWrapperTargetGlobal(caller *UnifiedNode, arg string, unifiedCG *UnifiedCallGraph) *UnifiedNode {
	if unifiedCG == nil {
		return nil
	}

	rawTarget, ok := parseWrappedFuncArg(arg)
	if !ok {
		return nil
	}

	bestScore := 0
	var best *UnifiedNode
	ambiguous := false

	callerKey := ""
	if caller != nil {
		callerKey = caller.Key
	}

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
		best = nil
	}
	if best != nil {
		return best
	}

	return resolveWrappedFuncValueTarget(caller, rawTarget, unifiedCG)
}

func wrappedTargetCandidates(callerKey, rawTarget string, unifiedCG *UnifiedCallGraph) []*UnifiedNode {
	if unifiedCG == nil {
		return nil
	}

	lookup := unifiedCG.getNodeLookup()
	if lookup == nil {
		return nil
	}

	seen := make(map[string]bool)
	var candidates []*UnifiedNode
	addCandidate := func(node *UnifiedNode) {
		if node == nil || seen[node.Key] {
			return
		}
		seen[node.Key] = true
		candidates = append(candidates, node)
	}
	addSlice := func(nodes []*UnifiedNode) {
		for _, node := range nodes {
			addCandidate(node)
		}
	}

	addCandidate(unifiedCG.Nodes[rawTarget])
	addSlice(lookup.byStripped[rawTarget])
	addSlice(lookup.byShort[rawTarget])
	if callerKey != "" {
		addSlice(lookup.byCallerPrefix[callerKey])
	}

	return candidates
}

func scoreWrappedTargetCandidate(callerKey, rawTarget, candidateKey string) int {
	switch {
	case rawTarget == candidateKey:
		return 130
	case rawTarget == stripPackageFromReceiver(candidateKey):
		return 125
	case rawTarget == shortFuncName(candidateKey):
		return 120
	case callerKey != "" && strings.HasPrefix(candidateKey, callerKey+"$"):
		return 110
	default:
		return 0
	}
}

func shortFuncName(funcName string) string {
	if funcName == "" {
		return ""
	}
	if idx := strings.LastIndex(funcName, ")."); strings.HasPrefix(funcName, "(") && idx != -1 {
		return funcName[idx+2:]
	}
	if idx := strings.LastIndex(funcName, "."); idx != -1 {
		return funcName[idx+1:]
	}
	return funcName
}

func stripPackageFromReceiver(funcName string) string {
	if funcName == "" || !strings.HasPrefix(funcName, "(") {
		return shortFuncName(funcName)
	}

	idx := strings.LastIndex(funcName, ").")
	if idx == -1 {
		return funcName
	}

	receiver := funcName[1:idx]
	prefix := ""
	typeName := receiver
	if strings.HasPrefix(typeName, "*") {
		prefix = "*"
		typeName = strings.TrimPrefix(typeName, "*")
	}
	if dot := strings.LastIndex(typeName, "."); dot != -1 {
		typeName = typeName[dot+1:]
	}

	return "(" + prefix + typeName + ")." + funcName[idx+2:]
}

func hasUnifiedEdge(caller, callee *UnifiedNode) bool {
	if caller == nil || callee == nil {
		return false
	}
	for _, edge := range caller.Out {
		if edge != nil && edge.Callee != nil && edge.Callee.Key == callee.Key {
			return true
		}
	}
	return false
}

func hasEquivalentUnifiedEdge(caller, callee *UnifiedNode, source string, vtaEdge *callgraph.Edge) bool {
	if caller == nil || callee == nil {
		return false
	}
	want := newVTAEdgeInfo(vtaEdge)
	for _, edge := range caller.Out {
		if edge == nil || edge.Callee == nil || edge.Callee.Key != callee.Key || edge.Source != source {
			continue
		}
		if sameVTAEdgeInfo(edge.VTA, want) {
			return true
		}
	}
	return false
}

func sameVTAEdgeInfo(a, b *VTAEdgeInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.HasSite == b.HasSite &&
		a.IsInvoke == b.IsInvoke &&
		a.IsDynamicFunc == b.IsDynamicFunc &&
		a.Arg0 == b.Arg0 &&
		a.SiteLine == b.SiteLine &&
		a.SiteCol == b.SiteCol
}

// hasRetainedUnifiedEdge reports whether caller already has an edge to callee
// that will survive BuildDAG. Pure invoke/dynamic VTA edges are dropped there,
// so they must not block the restorative EXTRA/Register Param edges.
func hasRetainedUnifiedEdge(caller, callee *UnifiedNode) bool {
	if caller == nil || callee == nil {
		return false
	}
	for _, edge := range caller.Out {
		if edge == nil || edge.Callee == nil || edge.Callee.Key != callee.Key {
			continue
		}
		if edge.VTA != nil && (edge.VTA.IsInvoke || edge.VTA.IsDynamicFunc) {
			continue
		}
		return true
	}
	return false
}
