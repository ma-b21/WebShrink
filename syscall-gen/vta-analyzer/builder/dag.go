package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"

	"github.com/bits-and-blooms/bitset"

	"vta-analyzer/utils"
)

// DAGNode 用于强连通分量计算和系统调用传播的节点
type DAGNode struct {
	Key           string
	Pos           string
	SyscallBitSet *bitset.BitSet
	OutEdges      []string // 出边指向的节点 key

	// Tarjan 算法辅助字段
	dfn     int
	low     int
	onStack bool
	sccID   int // 所属强连通分量 ID (-1 表示未分配)
}

// SCC 强连通分量
type SCC struct {
	ID            int
	Nodes         []*DAGNode
	SyscallBitSet *bitset.BitSet
	OutSCCs       []int // 指向其他 SCC 的边
	InSCCs        []int // 被其他 SCC 指向的边（用于反向传播）
}

// DAG 有向无环图（缩点后）
type DAG struct {
	Nodes map[string]*DAGNode
	SCCs  []*SCC
}

var runtimePrefixes = []string{
	"runtime.findRunnable",
	"runtime.schedule",
	"runtime.newproc",
	"runtime.newproc1",
	"runtime.execute",
	// "runtime.mcall",
	"runtime.runqgrab",
	"runtime.runqsteal",
	"runtime.sysmon",
	"runtime.retake",
	"runtime.preemptone",
	"runtime.morestack",
	// "runtime.systemstack",
	"runtime.gopark",
	"runtime.park_m",
	"runtime.gosched",
	"runtime.Gosched",
	"runtime.mstart",
	"runtime.mstart0",
	"runtime.mstart1",
	"runtime.mallocgc",

	// M (machine/thread) 管理 - 会连接回调度器
	"runtime.allocm",
	"runtime.startm",
	"runtime.newm",
	"runtime.newm1",
	"runtime.stopm",
	"runtime.handoffp",
	"runtime.wakep",
	"runtime.wirep",
	"runtime.acquirep",

	// P (processor) 管理
	"runtime.procresize",
	"(*runtime.p).destroy",

	// G 状态管理 - 会触发调度
	"runtime.casgstatus",
	"runtime.ready",
	"runtime.suspendG",
	"(*runtime.synctestGroup).changegstatus",

	// 死锁检测/安全点
	"runtime.checkdead",
	"runtime.stoplockedm",
	"runtime.runSafePointFn",

	// Heap 内部操作
	"runtime.mheap",

	// Sweep 相关
	"runtime.sweep",

	// Page allocator
	"runtime.page",
	"(*runtime.pallocData).findScavengeCandidate",
	"(*runtime.scavengeIndex).sysGrow",

	// Stack 分配
	"runtime.stack",

	// 其他内存相关
	"runtime.persistentalloc1",
	"runtime.getempty",
	"runtime.freeSpecial",
	"(*runtime.spanSet).push",
	"(*runtime.mcache).releaseAll",
	"runtime.newMarkBits",
	"runtime.wbBufFlush1",

	// trace相关
	"runtime.trace",

	// profiling相关
	"runtime.stkbucket",
	"runtime.saveg",
	"runtime.doRecordGoroutineProfile",
	"(*runtime.mLockProfile)",
}

func hasRuntimePrefix(s string) bool {
	for _, p := range runtimePrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// BuildDAG 从 UnifiedCallGraph 构建 DAG
func BuildDAG(ucg *UnifiedCallGraph) *DAG {
	dag := &DAG{
		Nodes: make(map[string]*DAGNode),
		SCCs:  make([]*SCC, 0),
	}

	for key, node := range ucg.Nodes {
		if hasRuntimePrefix(node.Key) {
			continue
		}
		dagNode := &DAGNode{
			Key:           key,
			Pos:           "",
			SyscallBitSet: node.SyscallBitSet.Clone(),
			OutEdges:      make([]string, 0, len(node.Out)),
			sccID:         -1,
			dfn:           -1, // -1 表示未访问
			low:           -1,
		}
		if node.HasSSA {
			dagNode.Pos = node.Pos
		}

		for _, edge := range node.Out {
			if edge.Callee == nil || hasRuntimePrefix(edge.Callee.Key) {
				continue
			}

			// 保留已经解析出具体 callee 的 interface invoke 边；
			// 只继续跳过真正无法静态落点的动态函数值调用（如 map[string]func）。
			if edge.VTA != nil && edge.VTA.IsDynamicFunc {
				continue
			}

			dagNode.OutEdges = append(dagNode.OutEdges, edge.Callee.Key)
		}

		dag.Nodes[key] = dagNode
	}

	return dag
}

// ComputeSCC 使用 Tarjan 算法计算强连通分量
func (d *DAG) ComputeSCC() {
	var (
		stack []*DAGNode
		index int = 1 // 从 1 开始，-1 表示未访问
		sccID int
	)

	// 允许在 ImportJSON 之后重新计算 SCC。
	// 导入场景下节点可能带有旧的 sccID/dfn，需要先清空运行时状态。
	d.SCCs = make([]*SCC, 0)
	for _, node := range d.Nodes {
		node.dfn = -1
		node.low = 0
		node.onStack = false
		node.sccID = -1
	}

	var tarjan func(node *DAGNode)
	tarjan = func(node *DAGNode) {
		node.dfn = index
		node.low = index
		index++
		node.onStack = true
		stack = append(stack, node)

		// 遍历所有出边
		for _, neighborKey := range node.OutEdges {
			neighbor, exists := d.Nodes[neighborKey]
			if !exists {
				continue
			}

			if neighbor.dfn == -1 { // 未访问
				tarjan(neighbor)
				if neighbor.low < node.low {
					node.low = neighbor.low
				}
			} else if neighbor.onStack { // 在栈中，说明形成环
				if neighbor.dfn < node.low {
					node.low = neighbor.dfn
				}
			}
		}

		// 如果是 SCC 的根节点
		if node.low == node.dfn {
			scc := &SCC{
				ID:            sccID,
				Nodes:         make([]*DAGNode, 0),
				SyscallBitSet: bitset.New(512),
				OutSCCs:       make([]int, 0),
				InSCCs:        make([]int, 0),
			}

			// 弹出栈中属于当前 SCC 的所有节点
			for {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				top.onStack = false
				top.sccID = sccID

				scc.Nodes = append(scc.Nodes, top)
				// 合并该节点的系统调用
				scc.SyscallBitSet.InPlaceUnion(top.SyscallBitSet)

				if top == node {
					break
				}
			}

			d.SCCs = append(d.SCCs, scc)
			sccID++
		}
	}

	// 对所有未访问的节点执行 Tarjan
	for _, node := range d.Nodes {
		if node.dfn == -1 {
			tarjan(node)
		}
	}
}

func (d *DAG) VerifySCC(sccID, epoch int) bool {
	if sccID < 0 || sccID >= len(d.SCCs) {
		return false
	}

	scc := d.SCCs[sccID]
	if len(scc.Nodes) <= 1 {
		return true
	}

	fmt.Printf("验证 SCC %d (大小: %d): 执行 10 轮随机可达性测试\n",
		sccID, len(scc.Nodes))

	// BFS 检查 node1 能否到达 node2
	canReach := func(from, to *DAGNode) bool {
		visited := make(map[string]bool)
		queue := []*DAGNode{from}
		visited[from.Key] = true

		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]

			if current.Key == to.Key {
				return true
			}

			for _, outKey := range current.OutEdges {
				// 只在 SCC 内部搜索
				inSCC := false
				var nextNode *DAGNode
				for _, n := range scc.Nodes {
					if n.Key == outKey {
						inSCC = true
						nextNode = n
						break
					}
				}

				if inSCC && !visited[outKey] {
					visited[outKey] = true
					queue = append(queue, nextNode)
				}
			}
		}
		return false
	}

	// 执行 10 轮测试
	passCount := 0
	for round := 1; round <= epoch; round++ {
		// 随机选择两个不同的节点
		idx1 := rand.Intn(len(scc.Nodes))
		idx2 := rand.Intn(len(scc.Nodes))

		// 确保选择的是不同的节点
		for idx1 == idx2 {
			idx2 = rand.Intn(len(scc.Nodes))
		}

		node1 := scc.Nodes[idx1]
		node2 := scc.Nodes[idx2]

		reach12 := canReach(node1, node2)
		reach21 := canReach(node2, node1)

		status := "✓"
		if !reach12 || !reach21 {
			status = "✗"
		} else {
			passCount++
		}

		fmt.Printf("  [%d/%d] %s %s <-> %s: %v & %v\n",
			round, epoch, status, node1.Key, node2.Key, reach12, reach21)

		// 如果某一轮失败，可以选择立即返回或继续测试
		if !reach12 || !reach21 {
			fmt.Printf("  ✗ 第 %d 轮测试失败！\n", round)
		}
	}

	fmt.Printf("验证结果: %d/%d 轮通过\n", passCount, epoch)

	return passCount == epoch
}

// BuildSCCGraph 构建 SCC 之间的 DAG
func (d *DAG) BuildSCCGraph() {
	sccOutEdges := make(map[int]map[int]bool)
	for i := range d.SCCs {
		sccOutEdges[i] = make(map[int]bool)
	}

	// 收集 SCC 之间的边
	for _, node := range d.Nodes {
		fromSCC := node.sccID
		for _, toKey := range node.OutEdges {
			toNode, exists := d.Nodes[toKey]
			if !exists {
				continue
			}
			toSCC := toNode.sccID

			// 跨 SCC 的边
			if fromSCC != toSCC {
				sccOutEdges[fromSCC][toSCC] = true
			}
		}
	}

	// 设置每个 SCC 的出边和入边
	for sccID, outSet := range sccOutEdges {
		for targetSCC := range outSet {
			d.SCCs[sccID].OutSCCs = append(d.SCCs[sccID].OutSCCs, targetSCC)
			d.SCCs[targetSCC].InSCCs = append(d.SCCs[targetSCC].InSCCs, sccID)
		}
	}
}

// PropagateSyscalls 基于拓扑排序传播系统调用（从叶子向根）
func (d *DAG) PropagateSyscalls() {
	// 计算每个 SCC 的出度（用于找叶子节点）
	outDegree := make([]int, len(d.SCCs))
	for _, scc := range d.SCCs {
		outDegree[scc.ID] = len(scc.OutSCCs)
	}

	// 找出所有出度为 0 的 SCC（叶子节点）
	queue := make([]int, 0)
	for i, degree := range outDegree {
		if degree == 0 {
			queue = append(queue, i)
		}
	}

	// 反向拓扑排序：从叶子向根传播
	processed := 0
	for len(queue) > 0 {
		sccID := queue[0]
		queue = queue[1:]
		processed++

		scc := d.SCCs[sccID]

		// 传播：当前 SCC 合并所有子节点（出边指向的 SCC）的系统调用
		for _, childSCCID := range scc.OutSCCs {
			childSCC := d.SCCs[childSCCID]
			scc.SyscallBitSet.InPlaceUnion(childSCC.SyscallBitSet)
		}

		// 处理所有父节点（入边来源的 SCC）
		for _, parentSCCID := range scc.InSCCs {
			outDegree[parentSCCID]--
			if outDegree[parentSCCID] == 0 {
				queue = append(queue, parentSCCID)
			}
		}
	}

	// 检查是否所有 SCC 都被处理
	if processed != len(d.SCCs) {
		// 理论上不应该发生，因为已经缩点了
	}

	// 将 SCC 的系统调用传播回节点
	for _, scc := range d.SCCs {
		for _, node := range scc.Nodes {
			node.SyscallBitSet = scc.SyscallBitSet.Clone()
		}
	}
}

// ExportJSON 导出 JSON 格式的结果
type DAGNodeJSON struct {
	Key         string   `json:"key"`
	Pos         string   `json:"pos"`
	Syscalls    []int    `json:"syscalls"`
	SyscallName []string `json:"syscall_names"`
	Callees     []string `json:"callees"`
	SCCID       int      `json:"scc_id"`
}

func (d *DAG) ExportJSON(outputPath string, syscallName bool) error {
	if len(d.Nodes) == 0 {
		return errors.New("DAG is empty")
	}

	var nodes []*DAGNodeJSON
	var syscallMap map[int]string
	var err error
	if syscallName {
		syscallMap, err = utils.LoadSyscallMap()
		if err != nil {
			log.Println("加载Syscall Map失败")
			syscallMap = nil
		}
	}

	// 导出所有节点及其系统调用集合
	for _, node := range d.Nodes {
		syscalls := bitsetToSlice(node.SyscallBitSet)
		nodeJSON := &DAGNodeJSON{
			Key:      node.Key,
			Pos:      node.Pos,
			Syscalls: syscalls,
			Callees:  node.OutEdges,
			SCCID:    node.sccID,
		}
		if syscallName && syscallMap != nil {
			for _, syscall := range syscalls {
				if syscallString, ok := syscallMap[syscall]; ok {
					nodeJSON.SyscallName = append(nodeJSON.SyscallName, syscallString)
				} else {
					continue
				}
			}
		}
		nodes = append(nodes, nodeJSON)
	}

	// 按 key 排序（可选，便于阅读）
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Key < nodes[j].Key
	})

	data, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

func (d *DAG) ImportJSON(inputPath string) error {
	// 读取文件
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// 解析 JSON
	var jsonNodes []*DAGNodeJSON
	if err := json.Unmarshal(data, &jsonNodes); err != nil {
		return err
	}

	// 初始化 Nodes Map
	d.Nodes = make(map[string]*DAGNode, len(jsonNodes))
	d.SCCs = nil

	// 遍历恢复 Node 数据
	for _, jNode := range jsonNodes {
		// 恢复 Syscall BitSet
		bs := bitset.New(512)
		for _, syscallID := range jNode.Syscalls {
			bs.Set(uint(syscallID))
		}

		node := &DAGNode{
			Key:           jNode.Key,
			Pos:           jNode.Pos,
			SyscallBitSet: bs,
			OutEdges:      jNode.Callees,
			sccID:         jNode.SCCID,
			dfn:           0,
			low:           0,
			onStack:       false,
		}

		d.Nodes[node.Key] = node
	}

	return nil
}

func (d *DAG) AddSyscallsToNode(funcName string, syscallNums []int) {
	node, exists := d.Nodes[funcName]
	if !exists {
		log.Printf("警告: 函数 %s 不存在于 DAG 中，无法添加系统调用\n", funcName)
		return
	}

	var sccBitSet *bitset.BitSet
	if node.sccID >= 0 && node.sccID < len(d.SCCs) && d.SCCs[node.sccID] != nil {
		sccBitSet = d.SCCs[node.sccID].SyscallBitSet
	}

	for _, scNum := range syscallNums {
		if !node.SyscallBitSet.Test(uint(scNum)) {
			log.Printf("添加系统调用 %d 到函数 %s\n", scNum, funcName)
		}
		node.SyscallBitSet.Set(uint(scNum))
		if sccBitSet != nil {
			sccBitSet.Set(uint(scNum))
		}
	}
}

// bitsetToSlice 将 bitset 转换为排序的 int 切片
func bitsetToSlice(bs *bitset.BitSet) []int {
	result := make([]int, 0, bs.Count())
	for i, e := bs.NextSet(0); e; i, e = bs.NextSet(i + 1) {
		result = append(result, int(i))
	}
	return result
}

// GetStats 获取 DAG 统计信息
func (d *DAG) GetStats() (nodeCount, edgeCount, sccCount, maxSCCSize int) {
	nodeCount = len(d.Nodes)
	sccCount = len(d.SCCs)

	for _, node := range d.Nodes {
		edgeCount += len(node.OutEdges)
	}

	for _, scc := range d.SCCs {
		if len(scc.Nodes) > maxSCCSize {
			maxSCCSize = len(scc.Nodes)
		}
	}

	return
}

// GetLargestSCC 获取最大的强连通分量
func (d *DAG) GetLargestSCC() *SCC {
	if len(d.SCCs) == 0 {
		return nil
	}

	largest := d.SCCs[0]
	for _, scc := range d.SCCs {
		if len(scc.Nodes) > len(largest.Nodes) {
			largest = scc
		}
	}

	return largest
}

// ExportSCCToDot 导出指定 SCC 的 DOT 格式
func (d *DAG) ExportSCCToDot(sccID int, filename string) error {
	if sccID < 0 || sccID >= len(d.SCCs) {
		return errors.New("invalid SCC ID")
	}

	scc := d.SCCs[sccID]

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "digraph scc_%d {\n", sccID)
	fmt.Fprintln(file, "  node [shape=box];")
	fmt.Fprintln(file, "  rankdir=TB;")
	fmt.Fprintf(file, "  label=\"SCC %d (Size: %d nodes)\";\n", sccID, len(scc.Nodes))
	fmt.Fprintln(file, "  labelloc=\"t\";")
	fmt.Fprintln(file)

	// 创建节点 ID 映射
	nodeIDs := make(map[string]int)
	nodeID := 0

	// 输出 SCC 内的所有节点
	for _, node := range scc.Nodes {
		nodeIDs[node.Key] = nodeID

		label := node.Key
		syscalls := bitsetToSlice(node.SyscallBitSet)
		if len(syscalls) > 0 {
			if len(syscalls) <= 5 {
				label = fmt.Sprintf("%s\\nSyscalls: %v", node.Key, syscalls)
			} else {
				label = fmt.Sprintf("%s\\nSyscalls: %d total", node.Key, len(syscalls))
			}
		}

		fmt.Fprintf(file, "  n%d [label=\"%s\"];\n", nodeID, escapeLabel(label))
		nodeID++
	}

	fmt.Fprintln(file)

	// 输出 SCC 内的边（只包含 SCC 内部的边）
	sccNodeSet := make(map[string]bool)
	for _, node := range scc.Nodes {
		sccNodeSet[node.Key] = true
	}

	for _, node := range scc.Nodes {
		callerID := nodeIDs[node.Key]
		for _, calleeKey := range node.OutEdges {
			// 只输出 SCC 内部的边
			if sccNodeSet[calleeKey] {
				calleeID := nodeIDs[calleeKey]
				fmt.Fprintf(file, "  n%d -> n%d;\n", callerID, calleeID)
			}
		}
	}

	fmt.Fprintln(file, "}")
	return nil
}

// ExportLargestSCCToDot 导出最大强连通分量的 DOT 格式
func (d *DAG) ExportLargestSCCToDot(filename string) error {
	largest := d.GetLargestSCC()
	if largest == nil {
		return errors.New("no SCC found")
	}

	return d.ExportSCCToDot(largest.ID, filename)
}

// ExportAllSCCsInfo 导出所有 SCC 的统计信息
func (d *DAG) ExportAllSCCsInfo(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "SCC Statistics:")
	fmt.Fprintln(file, "================")
	fmt.Fprintf(file, "Total SCCs: %d\n\n", len(d.SCCs))

	// 按大小排序 SCC
	type sccInfo struct {
		ID       int
		Size     int
		Syscalls int
	}

	infos := make([]sccInfo, 0, len(d.SCCs))
	for _, scc := range d.SCCs {
		infos = append(infos, sccInfo{
			ID:       scc.ID,
			Size:     len(scc.Nodes),
			Syscalls: int(scc.SyscallBitSet.Count()),
		})
	}

	// 按大小降序排序
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Size > infos[j].Size
	})

	fmt.Fprintln(file, "SCCs sorted by size:")
	fmt.Fprintln(file, "--------------------")
	for i, info := range infos {
		if info.Size > 1 { // 只显示包含多个节点的 SCC
			fmt.Fprintf(file, "%d. SCC %d: %d nodes, %d syscalls\n",
				i+1, info.ID, info.Size, info.Syscalls)

			// 显示前 10 个节点
			scc := d.SCCs[info.ID]
			fmt.Fprintln(file, "   Nodes:")
			for j, node := range scc.Nodes {
				if j >= 10 {
					fmt.Fprintf(file, "   ... and %d more\n", len(scc.Nodes)-5)
					break
				}
				fmt.Fprintf(file, "   - %s\n", node.Key)
			}
			fmt.Fprintln(file)
		}
	}

	return nil
}

func escapeLabel(s string) string {
	s = replaceAll(s, "\\", "\\\\")
	s = replaceAll(s, "\"", "\\\"")
	s = replaceAll(s, "\n", "\\n")
	return s
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old) - 1
		} else {
			result += string(s[i])
		}
	}
	return result
}
