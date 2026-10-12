package builder

import (
	asm "asm-analyzer/types"
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"os"
	"strings"

	"github.com/bits-and-blooms/bitset"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"vta-analyzer/utils"
)

// UnifiedNode 统一节点：可能是 Go 函数或汇编函数
type UnifiedNode struct {
	Key           string           // 唯一标识，如 "runtime.asmcgocall"
	HasSSA        bool             // 是否有 Go/SSA 节点信息
	Pos           string           // Go 函数位置
	Asm           *asm.AsmFunction // 汇编函数（可能为 nil）
	IsAsm         bool             // 是否是汇编函数
	IsAnonymous   bool             // 是否是匿名函数
	Syscalls      []int            // 系统调用列表
	SyscallBitSet *bitset.BitSet   // 系统调用bitset
	In            []*UnifiedEdge   // 入边
	Out           []*UnifiedEdge   // 出边
}

// VTAEdgeInfo 仅保留后续阶段真正需要的 VTA 元数据，
// 避免 UnifiedGraph 长期持有子图副本中的整条 callgraph.Edge。
type VTAEdgeInfo struct {
	HasSite       bool
	IsInvoke      bool
	IsDynamicFunc bool
	Arg0          string
	SiteLine      int
	SiteCol       int
}

// UnifiedEdge 统一边：可能来自 VTA 或汇编分析
type UnifiedEdge struct {
	Caller *UnifiedNode
	Callee *UnifiedNode
	VTA    *VTAEdgeInfo // VTA 边的轻量信息，可能为 nil
	Source string       // "vta" | "asm" | "builtin"
}

// UnifiedCallGraph 统一调用图
type UnifiedCallGraph struct {
	Root     *UnifiedNode
	Nodes    map[string]*UnifiedNode // key -> node
	Syscalls map[string][]int        // 汇总的系统调用

	nodeLookup *unifiedNodeLookup
}

type unifiedNodeLookup struct {
	byShort        map[string][]*UnifiedNode
	byStripped     map[string][]*UnifiedNode
	byCallerPrefix map[string][]*UnifiedNode
	byPosExact     map[string][]*UnifiedNode
	byPosLine      map[string][]*UnifiedNode
}

// 导出的 JSON 结构
type jsonEdge struct {
	Callee string       `json:"callee"`
	Source string       `json:"source,omitempty"`
	VTA    *VTAEdgeInfo `json:"vta,omitempty"`
}

type jsonNode struct {
	Key      string     `json:"key"`
	HasSSA   bool       `json:"has_ssa,omitempty"`
	Pos      string     `json:"pos,omitempty"`
	Syscalls []int      `json:"syscalls"`
	Callees  []string   `json:"callees,omitempty"`
	Edges    []jsonEdge `json:"edges,omitempty"`
}

func ImportSimpleTreeJSON(inputPath string) (*UnifiedCallGraph, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	var nodes []*jsonNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return nil, err
	}

	ucg := NewUnifiedCallGraph()
	for _, item := range nodes {
		if item == nil || item.Key == "" {
			continue
		}
		node := &UnifiedNode{
			Key:           item.Key,
			HasSSA:        item.HasSSA,
			Pos:           item.Pos,
			Asm:           nil,
			IsAsm:         false,
			IsAnonymous:   false,
			Syscalls:      append([]int(nil), item.Syscalls...),
			SyscallBitSet: bitset.New(512),
			In:            []*UnifiedEdge{},
			Out:           []*UnifiedEdge{},
		}
		for _, sysno := range item.Syscalls {
			if sysno >= 0 {
				node.SyscallBitSet.Set(uint(sysno))
			}
		}
		ucg.Nodes[item.Key] = node
		ucg.Syscalls[item.Key] = append([]int(nil), item.Syscalls...)
	}

	for _, item := range nodes {
		if item == nil || item.Key == "" {
			continue
		}
		caller := ucg.Nodes[item.Key]
		if caller == nil {
			continue
		}

		edges := item.Edges
		if len(edges) == 0 {
			edges = make([]jsonEdge, 0, len(item.Callees))
			for _, calleeKey := range item.Callees {
				edges = append(edges, jsonEdge{Callee: calleeKey})
			}
		}

		for _, edgeInfo := range edges {
			callee := ucg.Nodes[edgeInfo.Callee]
			if callee == nil {
				continue
			}
			edge := &UnifiedEdge{
				Caller: caller,
				Callee: callee,
				VTA:    cloneVTAEdgeInfo(edgeInfo.VTA),
				Source: edgeInfo.Source,
			}
			if edge.Source == "" {
				edge.Source = "import"
			}
			caller.Out = append(caller.Out, edge)
			callee.In = append(callee.In, edge)
		}
	}

	return ucg, nil
}

func (g *UnifiedCallGraph) ContainsNode(funcName string) bool {
	_, exist := g.Nodes[funcName]
	return exist
}

// 导出 JSON 的主函数
func (g *UnifiedCallGraph) ExportAsSimpleTreeJSON(outputPath string) error {
	if len(g.Nodes) == 0 {
		return errors.New("graph is empty")
	}

	// Serialize every node; the graph may have multiple roots.
	var jsons []*jsonNode
	for _, node := range g.Nodes {
		jsons = append(jsons, buildJSONNode(node))
	}

	data, err := json.MarshalIndent(jsons, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// 递归构造 JSON 结构
func buildJSONNode(n *UnifiedNode) *jsonNode {
	j := &jsonNode{
		Key:      n.Key,
		HasSSA:   n.HasSSA,
		Pos:      n.Pos,
		Syscalls: asm.NewSetFromSlice(n.Syscalls).ToSlice(),
		Callees:  []string{},
		Edges:    []jsonEdge{},
	}

	for _, e := range n.Out {
		j.Callees = append(j.Callees, e.Callee.Key)
		j.Edges = append(j.Edges, jsonEdge{
			Callee: e.Callee.Key,
			Source: e.Source,
			VTA:    cloneVTAEdgeInfo(e.VTA),
		})
	}

	return j
}

func cloneVTAEdgeInfo(info *VTAEdgeInfo) *VTAEdgeInfo {
	if info == nil {
		return nil
	}

	cloned := *info
	return &cloned
}

// NewUnifiedCallGraph 创建空的统一调用图
func NewUnifiedCallGraph() *UnifiedCallGraph {
	return &UnifiedCallGraph{
		Nodes:    make(map[string]*UnifiedNode),
		Syscalls: make(map[string][]int),
	}
}

func (ucg *UnifiedCallGraph) invalidateNodeLookup() {
	if ucg == nil {
		return
	}
	ucg.nodeLookup = nil
}

func (ucg *UnifiedCallGraph) getNodeLookup() *unifiedNodeLookup {
	if ucg == nil {
		return nil
	}
	if ucg.nodeLookup != nil {
		return ucg.nodeLookup
	}

	lookup := &unifiedNodeLookup{
		byShort:        make(map[string][]*UnifiedNode),
		byStripped:     make(map[string][]*UnifiedNode),
		byCallerPrefix: make(map[string][]*UnifiedNode),
		byPosExact:     make(map[string][]*UnifiedNode),
		byPosLine:      make(map[string][]*UnifiedNode),
	}

	for _, node := range ucg.Nodes {
		if node == nil {
			continue
		}

		lookup.byShort[shortFuncName(node.Key)] = append(lookup.byShort[shortFuncName(node.Key)], node)
		lookup.byStripped[stripPackageFromReceiver(node.Key)] = append(lookup.byStripped[stripPackageFromReceiver(node.Key)], node)

		if prefix := callerPrefixKey(node.Key); prefix != "" {
			lookup.byCallerPrefix[prefix] = append(lookup.byCallerPrefix[prefix], node)
		}

		if pos, ok := parseSourcePosition(node.Pos); ok {
			exactKey := sourcePositionKey(pos.File, pos.Line, pos.Col)
			lineKey := sourcePositionKey(pos.File, pos.Line, 0)
			lookup.byPosExact[exactKey] = append(lookup.byPosExact[exactKey], node)
			lookup.byPosLine[lineKey] = append(lookup.byPosLine[lineKey], node)
		}
	}

	ucg.nodeLookup = lookup
	return lookup
}

func callerPrefixKey(funcName string) string {
	if funcName == "" {
		return ""
	}
	idx := strings.Index(funcName, "$")
	if idx <= 0 {
		return ""
	}
	return funcName[:idx]
}

func sourcePositionKey(file string, line int, col int) string {
	return fmt.Sprintf("%s:%d:%d", file, line, col)
}

// AddOrGetNode 添加或获取节点
func (ucg *UnifiedCallGraph) AddOrGetNode(node *callgraph.Node, asmFunc *asm.AsmFunction, name string) (*UnifiedNode, bool) {
	key := ""
	if name != "" {
		key = name
	} else {
		if node != nil && asmFunc != nil {
			if node.Func.String() != asmFunc.FuncName {
				fmt.Println("ERROR When Add Node, Asm and Vta are not unified")
				return nil, false
			}
			key = asmFunc.FuncName
		} else if node != nil {
			key = node.Func.String()
		} else if asmFunc != nil {
			key = asmFunc.FuncName
		} else {
			fmt.Println("ERROR When Add Node, Asm and Vta are both nil")
			return nil, false
		}
	}

	if newNode, exists := ucg.Nodes[key]; exists {
		updatedLookup := false
		if newNode.Asm == nil {
			newNode.Asm = asmFunc
		}
		if node != nil && !newNode.HasSSA {
			newNode.HasSSA = true
			newNode.Pos = utils.GetFunctionPosition(node.Func)
			newNode.IsAnonymous = utils.IsAnonymous(node.Func)
			updatedLookup = true
		}
		newNode.IsAsm = (newNode.Asm != nil)
		if updatedLookup {
			ucg.invalidateNodeLookup()
		}
		return newNode, false
	}

	newNode := &UnifiedNode{
		Key:           key,
		HasSSA:        node != nil,
		Pos:           "",
		Asm:           asmFunc,
		IsAnonymous:   false,
		Syscalls:      []int{},
		SyscallBitSet: bitset.New(512),
		In:            []*UnifiedEdge{},
		Out:           []*UnifiedEdge{},
	}
	if node != nil {
		newNode.Pos = utils.GetFunctionPosition(node.Func)
		newNode.IsAnonymous = utils.IsAnonymous(node.Func)
	}
	ucg.Nodes[key] = newNode
	ucg.invalidateNodeLookup()
	return newNode, true
}

// AddEdge 添加边
func (ucg *UnifiedCallGraph) AddEdge(caller, callee *UnifiedNode, vtaEdge *callgraph.Edge, source string) *UnifiedEdge {
	edge := &UnifiedEdge{
		Caller: caller,
		Callee: callee,
		VTA:    newVTAEdgeInfo(vtaEdge),
		Source: source,
	}

	caller.Out = append(caller.Out, edge)
	callee.In = append(callee.In, edge)

	return edge
}

func newVTAEdgeInfo(vtaEdge *callgraph.Edge) *VTAEdgeInfo {
	if vtaEdge == nil {
		return nil
	}

	info := &VTAEdgeInfo{}
	if vtaEdge.Site == nil {
		return info
	}

	info.HasSite = true
	common := vtaEdge.Site.Common()
	if common == nil {
		return info
	}
	fillVTAEdgeInfo(info, common, vtaEdge.Caller.Func, vtaEdge.Site.Pos())
	return info
}

func fillVTAEdgeInfo(info *VTAEdgeInfo, common *ssa.CallCommon, callerFn *ssa.Function, pos token.Pos) {
	if info == nil || common == nil {
		return
	}

	info.IsInvoke = common.IsInvoke()
	info.IsDynamicFunc = !info.IsInvoke && common.StaticCallee() == nil
	if _, ok := common.Value.(*ssa.Builtin); ok {
		info.IsDynamicFunc = false
	}
	if callerFn != nil && callerFn.Prog != nil && callerFn.Prog.Fset != nil {
		position := callerFn.Prog.Fset.Position(pos)
		info.SiteLine = position.Line
		info.SiteCol = position.Column
	}
	if arg := firstLogicalCallArg(common); arg != nil {
		info.Arg0 = arg.String()
	}
}

func firstLogicalCallArg(common *ssa.CallCommon) ssa.Value {
	if common == nil || len(common.Args) == 0 {
		return nil
	}

	argIndex := 0
	if callHasReceiver(common) && len(common.Args) > 1 {
		argIndex = 1
	}
	if argIndex < 0 || argIndex >= len(common.Args) {
		return nil
	}
	return common.Args[argIndex]
}

func callHasReceiver(common *ssa.CallCommon) bool {
	if common == nil {
		return false
	}
	if common.IsInvoke() || common.Method != nil {
		return true
	}
	callee := common.StaticCallee()
	return callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil
}

// FindLeafNodes 查找叶子节点
func (ucg *UnifiedCallGraph) FindLeafNodes() []*UnifiedNode {
	var leaves []*UnifiedNode

	for _, node := range ucg.Nodes {
		if len(node.Out) == 0 && len(node.In) > 0 {
			leaves = append(leaves, node)
		}
	}

	return leaves
}

// GetNodeCount 获取节点数
func (ucg *UnifiedCallGraph) GetNodeCount() int {
	return len(ucg.Nodes)
}

// GetEdgeCount 获取边数
func (ucg *UnifiedCallGraph) GetEdgeCount() int {
	count := 0
	for _, node := range ucg.Nodes {
		count += len(node.Out)
	}
	return count
}
