package builder

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	// "sort"
	"errors"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/callgraph"
	// "golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/cheggaaa/pb/v3"

	asm "asm-analyzer/types"
	linktypes "linkname-analyzer/types"
	linkname "linkname-analyzer/utils"
	"vta-analyzer/utils"
)

type CallGraph struct {
	Root     *callgraph.Node
	Nodes    map[string]*callgraph.Node
	Syscalls map[string][]string
}

func (cg *CallGraph) CountNodesAndEdges() (nodes int, edges int) {
	if cg.Root == nil {
		return 0, 0
	}

	visited := make(map[*callgraph.Node]bool)

	var dfs func(n *callgraph.Node)
	dfs = func(n *callgraph.Node) {
		if visited[n] {
			return
		}
		visited[n] = true
		nodes++

		for _, e := range n.Out {
			edges++
			if e.Callee != nil {
				dfs(e.Callee)
			}
		}
	}

	dfs(cg.Root)
	return nodes, edges
}

func (cg *CallGraph) ReplaceNodeToTree(name string, tree *CallGraph) {
	node, exists := cg.Nodes[name]
	if !exists {
		log.Fatalf("图中没有可替换的节点 %s ", name)
	}
	delete(cg.Nodes, name)
	delete(cg.Syscalls, name)

	var replacementRoot *callgraph.Node
	if existingRoot := cg.Nodes[tree.Root.Func.String()]; existingRoot != nil {
		replacementRoot = existingRoot
	} else {
		replacementRoot = tree.Root
	}
	for _, edge := range node.In {
		edge.Callee = replacementRoot
		replacementRoot.In = append(replacementRoot.In, edge)
	}

	var Nodes []*callgraph.Node
	Nodes = append(Nodes, tree.Root)
	oldToNew := make(map[*callgraph.Node]*callgraph.Node)
	for len(Nodes) > 0 {
		node = Nodes[0]
		Nodes = Nodes[1:]

		var targetNode *callgraph.Node
		if existingNode := cg.Nodes[node.Func.String()]; existingNode != nil {
			targetNode = existingNode
		} else {
			targetNode = node
			cg.Nodes[node.Func.String()] = node
			cg.Syscalls[node.Func.String()] = []string{}
		}
		oldToNew[node] = targetNode
		for _, outEdge := range node.Out {
			if cg.Nodes[outEdge.Callee.Func.String()] == nil {
				Nodes = append(Nodes, outEdge.Callee)
			}
		}
	}

	for oldNode, newNode := range oldToNew {
		for _, outEdge := range oldNode.Out {
			if outEdge.Callee == nil || outEdge.Callee.Func == nil {
				continue
			}
			newCallee := oldToNew[outEdge.Callee]
			if newCallee == nil {
				newCallee = cg.Nodes[outEdge.Callee.Func.String()]
			}
			if newCallee == nil {
				continue
			}
			newEdge := &callgraph.Edge{
				Caller: newNode,
				Callee: newCallee,
				Site:   outEdge.Site,
			}
			newNode.Out = append(newNode.Out, newEdge)
			newCallee.In = append(newCallee.In, newEdge)
		}
	}
}

func (cg *CallGraph) FindLeafNodes() []*callgraph.Node {
	var leaves []*callgraph.Node
	seen := make(map[*callgraph.Node]bool)

	for fn := range cg.Nodes {
		node := cg.Nodes[fn]
		if node == nil {
			continue
		}

		if isLeafNode(node) {
			if !seen[node] {
				leaves = append(leaves, node)
				seen[node] = true
			}
		}
	}

	return leaves
}

func isLeafNode(node *callgraph.Node) bool {
	if node == nil {
		return false
	}

	hasOutEdge := false
	for _, edge := range node.Out {
		if edge.Callee != nil && edge.Callee.Func != nil {
			hasOutEdge = true
			break
		}
	}

	return !hasOutEdge && len(node.In) > 0
}

var (
	_builtinPath string
	once         sync.Once
	_initErr     error

	loadPathToCg          = make(map[string]*callgraph.Graph)
	loadPathToProg        = make(map[string]*ssa.Program)
	loadPathToPkgs        = make(map[string][]*packages.Package)
	loadPathTossaPkgs     = make(map[string][]*ssa.Package)
	loadPathAddedBuiltins = make(map[string]bool)

	BuildFlags = []string{}
)

func SetBuiltinDeclFile(path string) {
	_builtinPath = path
}

func initBuiltinPkgs() error {
	// 切换工作目录到 builtins 文件所在目录
	currentPath, err := os.Getwd()
	if err != nil {
		return err
	}
	_builtinWorkPath := strings.Split(_builtinPath, "=")[1]
	_builtinWorkPath = _builtinWorkPath[:strings.LastIndex(_builtinWorkPath, "/")]
	err = os.Chdir(_builtinWorkPath)
	if err != nil {
		return err
	}

	BuildFunctionCallGraph(_builtinPath, "", false)
	BuildFunctionCallGraph("runtime", "", false)

	// 恢复工作目录
	err = os.Chdir(currentPath)
	if err != nil {
		return err
	}
	return nil
}

func GetBuiltinPkgs() error {
	once.Do(func() {
		_initErr = initBuiltinPkgs()
	})
	return _initErr
}

func LoadDeclImplMap(jsonPath string) (map[string]linktypes.ImplInfo, error) {
	declImplMap, _, err := linkname.LoadLinknameMappings(jsonPath)
	if err != nil {
		return nil, err
	}
	return declImplMap, nil
}

var builtinMap = map[string]string{
	"makeslice": "makeSliceCall",
	"makemap":   "makeMapCall",
	"makechan":  "makeChanCall",
	"new":       "newCall",
	"append":    "appendCall",
	"copy":      "copyCall",
	"delete":    "deleteCall",
	"clear":     "clearCall",
	"close":     "closeCall",
	"panic":     "panicCall",
	"recover":   "recoverCall",
	"print":     "printCall",
	"println":   "printlnCall",
}

var runtimeFuncMap = map[string][]string{
	"makeslice": {
		"makeslice",
		"makeslice64",
		"makeslicecopy",
		"mallocgc",
		"memmove",
		"panicmakeslicelen",
		"panicmakeslicecap",
	},
	"makemap": {
		"rand32",
		"makemap_small",
		"makemap",
		"makemap64",
	},
	"makechan": {
		"makechan",
		"makechan64",
	},
	"new": {
		"newobject",
	},
	"append": {
		"panicmakeslicelen",
		"growslice",
		"memclrNoHeapPointers",
		"memclrHasPointers",
		"typedslicecopy",
		"slicecopy",
		"memmove",
	},
	"copy": {
		"makeslicecopy",
		"mallocgc",
		"memmove",
		"typedslicecopy",
		"slicecopy",
	},
	"delete": {
		"mapdelete",
		"mapdelete_fast32",
		"mapdelete_fast64",
		"mapdelete_faststr",
	},
	"clear": {
		"memclrHasPointers",
		"memclrNoHeapPointers",
		"mapclear",
	},
	"close": {
		"closechan",
	},
	"panic": {
		"gopanic",
	},
	"recover": {
		"gorecover",
	},
	"print": {
		"printlock",
		"printeface",
		"printiface",
		"printuintptr",
		"printpointer",
		"printslice",
		"printhex",
		"printuint",
		"printint",
		"printfloat",
		"printcomplex",
		"printbool",
		"printsp",
		"printnl",
		"printstring",
		"printunlock",
	},
}

// GetBuiltinSubGraphNodes 为指定的 builtin 创建子调用图
// builtinName: builtin 函数名（如 "makeslice", "new" 等）
// 返回: 包含 builtin → runtime 边的子图
func GetBuiltinSubGraphNode(builtinName string) *callgraph.Node {
	// 检查 builtinName 是否支持
	if builtinName == "println" {
		builtinName = "print"
	}
	if _, ok := builtinMap[builtinName]; !ok {
		log.Printf("builtin function not supported: %s\n", builtinName)
		return nil
	}
	if _, ok := runtimeFuncMap[builtinName]; !ok {
		log.Printf("runtime functions for builtin not found: %s\n", builtinName)
		return nil
	}

	return buildBuiltinsSubGraph(builtinMap[builtinName], runtimeFuncMap[builtinName])
}

// buildBuiltinsSubGraph 创建 builtins 的子调用图
func buildBuiltinsSubGraph(builtinFuncName string, runtimeFuncNames []string) *callgraph.Node {
	// 找到 builtin 函数
	err := GetBuiltinPkgs()
	if err != nil {
		log.Println("failed to get builtin packages:", err)
		return nil
	}

	builtinFunc := loadPathTossaPkgs[_builtinPath][0].Func(builtinFuncName)
	if builtinFunc == nil {
		log.Printf("builtin function SSA not found: %s\n", builtinFuncName)
		return nil
	}
	builtinNode := loadPathToCg[_builtinPath].Nodes[builtinFunc]
	if builtinNode == nil {
		log.Printf("builtin function callgraph node not found: %s\n", builtinFuncName)
		return nil
	}
	if len(builtinNode.Out) > 0 {
		return builtinNode
	}

	// 加载 runtime 包
	if len(loadPathTossaPkgs["runtime"]) == 0 || loadPathToCg["runtime"] == nil {
		log.Printf("runtime package cache not ready for builtin: %s\n", builtinFuncName)
		return nil
	}
	runtimePkg := loadPathTossaPkgs["runtime"][0]
	runtimeNodes := loadPathToCg["runtime"].Nodes

	for _, fnName := range runtimeFuncNames {
		runtimeFunc := runtimePkg.Func(fnName)
		if runtimeFunc == nil {
			log.Printf("runtime function not found: %s\n", fnName)
			continue
		}

		runtimeNode := runtimeNodes[runtimeFunc]

		// 构建调用边
		edge := &callgraph.Edge{
			Caller: builtinNode,
			Callee: runtimeNode,
		}
		builtinNode.Out = append(builtinNode.Out, edge)
		runtimeNode.In = append(runtimeNode.In, edge)
	}

	return builtinNode
}

func collectPackagesByPath(pkgs []*packages.Package) map[string]*packages.Package {
	pkgByPath := make(map[string]*packages.Package)
	var visit func(pkg *packages.Package)
	visit = func(pkg *packages.Package) {
		if pkg == nil || pkg.PkgPath == "" {
			return
		}
		if _, exists := pkgByPath[pkg.PkgPath]; exists {
			return
		}
		pkgByPath[pkg.PkgPath] = pkg
		for _, imported := range pkg.Imports {
			visit(imported)
		}
	}

	for _, pkg := range pkgs {
		visit(pkg)
	}

	return pkgByPath
}

func registerLoadedProgram(loadPath string, pkgs []*packages.Package, prog *ssa.Program, ssaPkgs []*ssa.Package, vtaGraph *callgraph.Graph) {
	loadPath = normalizeLoadPath(loadPath)
	if vtaGraph != nil {
		loadPathToCg[loadPath] = vtaGraph
	}
	loadPathToPkgs[loadPath] = pkgs
	loadPathToProg[loadPath] = prog
	loadPathTossaPkgs[loadPath] = ssaPkgs

	pkgByPath := collectPackagesByPath(pkgs)
	for _, ssaPkg := range prog.AllPackages() {
		if ssaPkg == nil || ssaPkg.Pkg == nil {
			continue
		}

		pkgPath := ssaPkg.Pkg.Path()
		if vtaGraph != nil {
			loadPathToCg[pkgPath] = vtaGraph
		}
		loadPathToProg[pkgPath] = prog
		loadPathTossaPkgs[pkgPath] = []*ssa.Package{ssaPkg}
		if pkg, exists := pkgByPath[pkgPath]; exists {
			loadPathToPkgs[pkgPath] = []*packages.Package{pkg}
		}
		log.Printf("缓存 %s 中的包 %s\n", loadPath, pkgPath)
	}
}

func normalizeLoadPath(loadPath string) string {
	if strings.HasPrefix(loadPath, "std/") {
		return strings.TrimPrefix(loadPath, "std/")
	}
	return loadPath
}

func loadPackagesAndSSA(loadPath string) ([]*packages.Package, *ssa.Program, []*ssa.Package) {
	loadPath = normalizeLoadPath(loadPath)
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
		BuildFlags: BuildFlags,
	}

	pkgs, err := packages.Load(cfg, loadPath)
	if err != nil {
		log.Fatalf("加载包失败: %v", err)
	}

	// 从 go.mod 读取当前模块名，用于区分模块内包与外部依赖
	modName := ""
	if data, err := os.ReadFile("go.mod"); err == nil {
		if f, err := modfile.Parse("go.mod", data, nil); err == nil {
			modName = f.Module.Mod.Path
		}
	}

	hasFatal := false
	ignorePaths := ignoredDirectPkgErrorPaths()
	visited := map[string]bool{}
	var walkErrors func(pkg *packages.Package)
	walkErrors = func(pkg *packages.Package) {
		if pkg == nil || visited[pkg.PkgPath] {
			return
		}
		visited[pkg.PkgPath] = true
		for _, e := range pkg.Errors {
			if modName != "" && strings.HasPrefix(pkg.PkgPath, modName) && !shouldIgnoreDirectPkgError(pkg.PkgPath, ignorePaths) {
				log.Printf("直接包错误 [%s]: %v", pkg.PkgPath, e)
				hasFatal = true
			} else if modName != "" && strings.HasPrefix(pkg.PkgPath, modName) {
				log.Printf("IGNORED 直接包错误 [%s]: %v", pkg.PkgPath, e)
			} else {
				log.Printf("WARNING: 跳过传递依赖错误 [%s]: %v", pkg.PkgPath, e)
			}
		}
		for _, imp := range pkg.Imports {
			walkErrors(imp)
		}
	}
	for _, pkg := range pkgs {
		walkErrors(pkg)
	}
	if hasFatal {
		log.Fatal("直接包中存在错误")
	}

	// 过滤掉有错误的包，避免 SSA 构建时 nil pointer
	var cleanPkgs []*packages.Package
	for _, pkg := range pkgs {
		if pkg != nil && !pkg.IllTyped {
			cleanPkgs = append(cleanPkgs, pkg)
		} else if pkg != nil {
			log.Printf("SSA: 跳过有问题的包 [%s] (IllTyped=%v, errors=%d)", pkg.PkgPath, pkg.IllTyped, len(pkg.Errors))
		}
	}

	// 构建SSA
	prog, ssaPkgs := ssautil.AllPackages(cleanPkgs, ssa.InstantiateGenerics)
	prog.Build()
	return pkgs, prog, ssaPkgs
}

func ignoredDirectPkgErrorPaths() []string {
	raw := strings.TrimSpace(os.Getenv("VTA_IGNORE_DIRECT_PKG_ERRORS"))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func shouldIgnoreDirectPkgError(pkgPath string, ignorePaths []string) bool {
	for _, path := range ignorePaths {
		if pkgPath == path || strings.HasPrefix(pkgPath, path+"/") {
			return true
		}
	}
	return false
}

func ensureProgramLoaded(loadPath string) {
	loadPath = normalizeLoadPath(loadPath)
	if prog := loadPathToProg[loadPath]; prog != nil {
		return
	}

	pkgs, prog, ssaPkgs := loadPackagesAndSSA(loadPath)
	registerLoadedProgram(loadPath, pkgs, prog, ssaPkgs, nil)
}

func canonicalMainPkgFromCache(mainPkg string) string {
	if mainPkg == "" {
		return ""
	}

	// 这里只复用已经存在的缓存，不主动触发整包 SSA/VTA 加载。
	// subprocess 模式只需要把 runtime 中的 main.* 名称映射到调用者显式传入的
	// -main-pkg；如果为了“规范化”在这里提前加载整个主程序，会显著放大内存占用。
	pkgs, exists := loadPathToPkgs[mainPkg]
	if !exists {
		return mainPkg
	}
	if len(pkgs) == 0 || pkgs[0] == nil {
		return mainPkg
	}

	return pkgs[0].String()
}

const vtaCacheDir = "/tmp/vta-cache"

func diskVtaCacheEnabled() bool {
	return os.Getenv("VTA_DISABLE_DISK_CACHE") == ""
}

func vtaCacheKey(loadPath string) string {
	scope := loadPath
	if strings.HasPrefix(loadPath, ".") {
		if cwd, err := os.Getwd(); err == nil {
			scope = filepath.Clean(cwd) + "\x00" + loadPath
		}
	}
	return fmt.Sprintf("%x", []byte(scope))
}

type vtaCacheEntry struct {
	Nodes     map[string]int      `json:"nodes"`     // funcName -> nodeID
	Adjacency map[string][]string `json:"adjacency"` // funcName -> [calleeNames]
}

func loadVtaCache(loadPath string) *vtaCacheEntry {
	if !diskVtaCacheEnabled() {
		return nil
	}
	cacheFile := filepath.Join(vtaCacheDir, vtaCacheKey(loadPath)+".json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil
	}
	var entry vtaCacheEntry
	if json.Unmarshal(data, &entry) != nil || len(entry.Nodes) == 0 {
		return nil
	}
	return &entry
}

func saveVtaCache(loadPath string, cg *callgraph.Graph) {
	if !diskVtaCacheEnabled() {
		return
	}
	os.MkdirAll(vtaCacheDir, 0755)
	entry := vtaCacheEntry{
		Nodes:     make(map[string]int),
		Adjacency: make(map[string][]string),
	}
	for fn, node := range cg.Nodes {
		if fn == nil || node == nil {
			continue
		}
		name := fn.String()
		entry.Nodes[name] = node.ID
	}
	for fn, node := range cg.Nodes {
		if fn == nil || node == nil {
			continue
		}
		name := fn.String()
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				entry.Adjacency[name] = append(entry.Adjacency[name], edge.Callee.Func.String())
			}
		}
	}
	cacheFile := filepath.Join(vtaCacheDir, vtaCacheKey(loadPath)+".json")
	data, _ := json.MarshalIndent(entry, "", "  ")
	os.WriteFile(cacheFile, data, 0644)
	fmt.Printf("VTA 缓存已保存: %s (%d 节点)\n", cacheFile, len(entry.Nodes))
}

func analyzePackage(loadPath string) {
	loadPath = normalizeLoadPath(loadPath)

	// Phase 1: 加载包 + 构建 SSA。若当前进程里已经缓存过同一 loadPath 的
	// SSA/program，则直接复用，避免 linkname/asm/webshrink-static 阶段先通过
	// GetAvailableFunctions 载入一次、随后又在这里整包重载一次。
	pkgs := loadPathToPkgs[loadPath]
	prog := loadPathToProg[loadPath]
	ssaPkgs := loadPathTossaPkgs[loadPath]
	if prog == nil || len(ssaPkgs) == 0 || len(pkgs) == 0 {
		pkgs, prog, ssaPkgs = loadPackagesAndSSA(loadPath)
	}

	// Phase 2: 检查 VTA 磁盘缓存，命中则跳过 RTA+VTA 计算
	if cached := loadVtaCache(loadPath); cached != nil {
		fmt.Printf("从缓存重建 VTA 图: %s (%d 节点)\n", loadPath, len(cached.Nodes))
		vtaGraph := rebuildCallGraphFromCache(cached, prog)
		registerLoadedProgram(loadPath, pkgs, prog, ssaPkgs, vtaGraph)
		return
	}

	allFuncs := ssautil.AllFunctions(prog)

	fmt.Printf("开始对 %s 执行 VTA 分析（带泛型补丁）...\n", loadPath)

	var roots []*ssa.Function
	for fn := range allFuncs {
		if fn.TypeParams().Len() == 0 && fn.Pkg != nil && fn.Pkg.Pkg != nil {
			roots = append(roots, fn)
		}
	}
	rtaResult := rta.Analyze(roots, true)

	if rtaResult == nil || rtaResult.CallGraph == nil {
		log.Printf("WARNING: RTA 返回 nil，使用空图继续")
		rtaResult = &rta.Result{CallGraph: callgraph.New(nil)}
	}
	vtaGraph := vta.CallGraph(allFuncs, rtaResult.CallGraph)

	// 保存 VTA 结果到磁盘缓存
	saveVtaCache(loadPath, vtaGraph)

	registerLoadedProgram(loadPath, pkgs, prog, ssaPkgs, vtaGraph)
}

// rebuildCallGraphFromCache 从磁盘缓存重建 callgraph.Graph
func rebuildCallGraphFromCache(cached *vtaCacheEntry, prog *ssa.Program) *callgraph.Graph {
	cg := callgraph.New(nil)

	// 建立 funcName -> *ssa.Function 查找表。这里必须覆盖方法、闭包、包装器等所有 SSA 函数，
	// 不能只看 pkg.Members，否则缓存重建后的 cg.Nodes 会丢失大量非包级函数节点。
	nameToFn := make(map[string]*ssa.Function)
	for fn := range ssautil.AllFunctions(prog) {
		if fn != nil {
			nameToFn[fn.String()] = fn
		}
	}

	// 创建所有节点
	nameToNode := make(map[string]*callgraph.Node)
	for name, id := range cached.Nodes {
		fn := nameToFn[name]
		node := &callgraph.Node{
			Func: fn,
			ID:   id,
			In:   make([]*callgraph.Edge, 0),
			Out:  make([]*callgraph.Edge, 0),
		}
		nameToNode[name] = node
		if fn != nil {
			cg.Nodes[fn] = node
		}
	}

	// 重建边
	for callerName, callees := range cached.Adjacency {
		callerNode := nameToNode[callerName]
		if callerNode == nil {
			continue
		}
		for _, calleeName := range callees {
			calleeNode := nameToNode[calleeName]
			if calleeNode == nil {
				continue
			}
			edge := &callgraph.Edge{
				Caller: callerNode,
				Callee: calleeNode,
			}
			callerNode.Out = append(callerNode.Out, edge)
			calleeNode.In = append(calleeNode.In, edge)
		}
	}

	return cg
}

// 构建指定函数的调用图
func BuildFunctionCallGraph(loadPath string, targetFunc string, needBuiltins bool) (*CallGraph, error) {
	loadPath = normalizeLoadPath(loadPath)
	if cg, exists := loadPathToCg[loadPath]; !exists || cg == nil {
		analyzePackage(loadPath)
	}

	cg := loadPathToCg[loadPath]
	prog := loadPathToProg[loadPath]
	pkgs := loadPathToPkgs[loadPath]

	if needBuiltins {
		if !loadPathAddedBuiltins[loadPath] {
			// 添加内置函数调用
			addBuiltinCalls(cg)
			loadPathAddedBuiltins[loadPath] = true
		}
	}

	// 如果指定了目标函数，过滤调用图
	if targetFunc != "" {
		// 查找目标函数
		targetSSAFunc := utils.FindFunction(prog, pkgs, targetFunc)
		if targetSSAFunc == nil {
			return nil, errors.New("未找到函数")
		}

		// 获取目标函数的节点
		if cg.Nodes[targetSSAFunc] == nil {
			log.Printf("函数 %s 在调用图中没有节点，跳过该目标函数\n", targetFunc)
			return nil, nil
		}

		return BuildSubgraph(cg.Nodes[targetSSAFunc]), nil
	}

	return nil, nil
}

func BuildSubgraph(root *callgraph.Node) *CallGraph {
	subgraph := &CallGraph{Nodes: make(map[string]*callgraph.Node), Syscalls: make(map[string][]string)}

	oldToNew := make(map[*callgraph.Node]*callgraph.Node)

	visited := make(map[*callgraph.Node]bool)
	queue := []*callgraph.Node{root}
	visited[root] = true

	// 第一遍：BFS 收集所有可达节点
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if node.Func == nil {
			continue
		}
		key := node.Func.String()
		newNode := subgraph.Nodes[key]
		if newNode == nil {
			newNode = &callgraph.Node{
				Func: node.Func,
				ID:   node.ID,
				In:   make([]*callgraph.Edge, 0),
				Out:  make([]*callgraph.Edge, 0),
			}
			subgraph.Nodes[key] = newNode
			subgraph.Syscalls[key] = []string{}
		}
		oldToNew[node] = newNode

		for _, edge := range node.Out {
			if edge.Callee != nil && !visited[edge.Callee] {
				visited[edge.Callee] = true
				queue = append(queue, edge.Callee)
			}
		}
	}

	// 第二遍：重建边
	for oldNode, newNode := range oldToNew {
		for _, oldEdge := range oldNode.Out {
			var newCallee *callgraph.Node

			if oldEdge.Callee == nil || oldEdge.Callee.Func == nil {
				continue
			}
			if existingCallee, exists := subgraph.Nodes[oldEdge.Callee.Func.String()]; exists {
				// callee 已经在 BFS 中访问过
				newCallee = existingCallee
			} else {
				log.Println("存在未遍历的新节点")
				continue
			}

			// 创建边
			newEdge := &callgraph.Edge{
				Caller: newNode,
				Callee: newCallee,
				Site:   oldEdge.Site,
			}

			newNode.Out = append(newNode.Out, newEdge)
			newCallee.In = append(newCallee.In, newEdge)
		}
	}

	subgraph.Root = oldToNew[root]

	return subgraph
}

// addBuiltinCalls 遍历调用图，识别 builtin 调用并添加到图中
func addBuiltinCalls(cg *callgraph.Graph) {
	// 遍历所有节点
	for fn, node := range cg.Nodes {
		if fn == nil || node == nil {
			continue
		}

		// 遍历函数的所有基本块和指令
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				builtinName := identifyBuiltinCall(instr)
				if builtinName == "" {
					continue // 不是 builtin 调用
				}

				builtinNode := GetBuiltinSubGraphNode(builtinName)
				if builtinNode == nil {
					continue
				}

				// 创建边：当前函数 → builtin
				var site ssa.CallInstruction
				if call, ok := instr.(ssa.CallInstruction); ok {
					site = call
				}
				edge := &callgraph.Edge{
					Caller: node,
					Callee: builtinNode,
					Site:   site, // 可能为nil
				}
				node.Out = append(node.Out, edge)
				builtinNode.In = append(builtinNode.In, edge)
			}
		}
	}
}

// identifyBuiltinCall 识别指令是否是 builtin 调用，返回 builtin 名称
func identifyBuiltinCall(instr ssa.Instruction) string {
	// 识别 make 相关
	switch instr := instr.(type) {
	case *ssa.MakeSlice:
		return "makeslice"
	case *ssa.MakeMap:
		return "makemap"
	case *ssa.MakeChan:
		return "makechan"
	case *ssa.Alloc:
		if instr.Heap {
			return "new"
		}
	case *ssa.Call:
		// 识别其他 builtin 调用
		if builtin := instr.Common().Value; builtin != nil {
			if b, ok := builtin.(*ssa.Builtin); ok {
				switch b.Name() {

				case "append":
					return "append"
				case "copy":
					return "copy"
				case "delete":
					return "delete"
				case "close":
					return "close"
				case "panic":
					return "panic"
				case "recover":
					return "recover"
				case "print":
					return "print"
				case "println":
					return "println"
				case "clear":
					return "clear"
				}
			}
		}
	}

	return ""
}

func LoadAsmCallGraphFromFile(path string) (map[string]*asm.AsmFunction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var funcs []asm.AsmFunction
	if err := json.Unmarshal(data, &funcs); err != nil {
		return nil, err
	}

	asmFuncMap := make(map[string]*asm.AsmFunction)
	for i := range funcs {
		asmFuncMap[funcs[i].FuncName] = &funcs[i]
	}

	return asmFuncMap, nil
}

func GetLinkNameExtendedVtaGraph(loadPath, targetFunc string, declImplMap map[string]linktypes.ImplInfo) *CallGraph {
	vtaGraph, err := BuildFunctionCallGraph(loadPath, targetFunc, true)
	if err != nil {
		return nil
	}
	if vtaGraph == nil {
		return nil
	}

	var queue []string
	queued := make(map[string]bool)

	enqueueIfExpandableLeaf := func(funcName string) {
		if queued[funcName] {
			return
		}
		node := vtaGraph.Nodes[funcName]
		if node == nil || !isLeafNode(node) {
			return
		}
		if _, exists := declImplMap[funcName]; !exists {
			return
		}
		queue = append(queue, funcName)
		queued[funcName] = true
	}

	for _, leaf := range vtaGraph.FindLeafNodes() {
		if leaf == nil || leaf.Func == nil {
			continue
		}
		enqueueIfExpandableLeaf(leaf.Func.String())
	}

	for len(queue) > 0 {
		leafName := queue[0]
		queue = queue[1:]
		delete(queued, leafName)

		leaf := vtaGraph.Nodes[leafName]
		if leaf == nil || !isLeafNode(leaf) {
			continue
		}

		implInfo, exists := declImplMap[leafName]
		if !exists {
			continue
		}

		subVtaGraph, err := BuildFunctionCallGraph(implInfo.ImplPkg, implInfo.ImplFunc, true)
		if err != nil {
			log.Fatalln("Err: ", err)
		}

		vtaGraph.ReplaceNodeToTree(leafName, subVtaGraph)

		for funcName := range subVtaGraph.Nodes {
			enqueueIfExpandableLeaf(funcName)
		}
	}

	return vtaGraph
}

var extraCallerCache = make(map[string]string)
var loadPathToAvailableFuncs = make(map[string][]string)

func GetAvailableFunctions(loadPath string) []string {
	loadPath = normalizeLoadPath(loadPath)
	if funcs, ok := loadPathToAvailableFuncs[loadPath]; ok {
		return funcs
	}

	ensureProgramLoaded(loadPath)
	prog := loadPathToProg[loadPath]
	pkgs := loadPathToPkgs[loadPath]
	funcs := utils.FindAvailableFunctions(prog, pkgs)
	sort.Strings(funcs)
	loadPathToAvailableFuncs[loadPath] = funcs
	return funcs
}

func GetVtaGraphsForModule(loadPath string, mainPkg string, declImplMap map[string]linktypes.ImplInfo, extraCalls map[string]CallInfo) *UnifiedCallGraph {
	BuildFunctionCallGraph("runtime", "", true) // 先把 builtins 加入到 runtime 图中
	BuildFunctionCallGraph(loadPath, "", true)
	mainPkg = canonicalMainPkgFromCache(mainPkg)
	funcs := GetAvailableFunctions(loadPath)
	log.Println(loadPath, "可用函数有:")
	log.Println(" - ", "==== FuncName ====", "==== IsAnonymous ====")
	for _, funcName := range funcs {
		log.Println(" - ", funcName)
	}

	// 合并调用图
	var unifiedGraph *UnifiedCallGraph = nil
	// 转换 VTA 图
	bar := pb.StartNew(len(funcs))
	for _, targetFunc := range funcs {
		bar.Increment()
		if unifiedGraph != nil && unifiedGraph.ContainsNode(targetFunc) {
			continue
		}
		vtaGraph := GetLinkNameExtendedVtaGraph(loadPath, targetFunc, declImplMap)
		unifiedGraph = MergeCallGraphs(unifiedGraph, vtaGraph, nil, declImplMap)
	}
	bar.Finish()

	log.Printf("初始VTA调用图构建完成，包含 %d 个节点\n", len(unifiedGraph.Nodes))

	extraLoadResult := make(map[string]bool)
	successfulExtraLoads := 0

	addExtra := func(targetFunc, loadPath string) bool {
		cacheKey := loadPath + "\x00" + targetFunc
		if ok, exists := extraLoadResult[cacheKey]; exists {
			return ok
		}
		if unifiedGraph.ContainsNode(targetFunc) {
			extraLoadResult[cacheKey] = true
			return true
		}
		vtaGraph := GetLinkNameExtendedVtaGraph(loadPath, targetFunc, declImplMap)
		if vtaGraph == nil {
			extraLoadResult[cacheKey] = false
			return false
		}
		unifiedGraph = MergeCallGraphs(unifiedGraph, vtaGraph, nil, declImplMap)
		extraLoadResult[cacheKey] = true
		successfulExtraLoads++
		// 预加载阶段会临时构造很多 subgraph，定期触发 GC 有助于把这些
		// 短命对象及时回收，降低峰值内存，而不改变分析语义。
		if successfulExtraLoads%16 == 0 {
			runtime.GC()
		}
		return true
	}

	log.Printf("开始添加额外接口调用与反射调用...\n")

	bar = pb.StartNew(len(extraCalls))
	for caller, callInfo := range extraCalls {
		bar.Increment()
		loadPath, targetFunc := utils.ParseRuntimeNameWithMainPkg(caller, mainPkg)
		if suppressedExtraEdgeCallers[targetFunc] {
			continue
		}
		callerSSAName := targetFunc
		if !addExtra(targetFunc, loadPath) {
			if callerNode := resolveCallerNodeFromSource(callInfo, unifiedGraph, mainPkg); callerNode != nil {
				extraCallerCache[caller] = callerNode.Key
				callerSSAName = callerNode.Key
			} else {
				ssaFunc, err := getSSAFunctionFallback(callInfo.CallerPathWithLine())
				if err != nil {
					log.Printf("WARNING: 无法为额外函数 %s 构建 VTA 图，且反查 SSA 函数失败: %v\n", caller, err)
					continue
				}
				addExtra(ssaFunc.String(), ssaFunc.Pkg.Pkg.Path())
				extraCallerCache[caller] = ssaFunc.String()
				callerSSAName = ssaFunc.String()
			}
		}

		callerNode := unifiedGraph.Nodes[callerSSAName]
		if callerNode == nil {
			log.Printf("WARNING: 额外边调用者 %s 无法在统一图中定位，跳过\n", caller)
			continue
		}
		for _, callee := range callInfo.Callee {
			resolved := false
			for _, candidate := range extraRuntimeNameCandidates(callee.RuntimeName, mainPkg) {
				if !addExtra(candidate.SSAName, candidate.PkgPath) {
					continue
				}
				extraCalleeCache[callee.cacheKey(caller)] = candidate.SSAName
				resolved = true
				break
			}
			if resolved {
				continue
			}

			if calleeNode, _ := resolveCalleeNode(caller, callInfo, callerNode, callee, unifiedGraph, mainPkg); calleeNode != nil {
				continue
			}

			log.Printf(
				"WARNING: 无法为额外被调函数 %s 找到 SSA 对应项 (caller=%s site=%s:%d:%d)\n",
				callee.RuntimeName,
				caller,
				callInfo.File,
				callee.CallsiteLine,
				callee.CallsiteCol,
			)
		}
	}
	bar.Finish()

	return unifiedGraph
}
