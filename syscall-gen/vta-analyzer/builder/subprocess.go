package builder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/types"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"vta-analyzer/utils"
)

type ssaLookupCacheEntry struct {
	prog *ssa.Program
	pkg  *ssa.Package
}

type procMeta struct {
	Pid     int
	PPid    int
	Name    string
	ExePath string
	Cmdline string
}

var ssaLookupCache = map[string]ssaLookupCacheEntry{}

func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func isWorkspaceRoot(dir string) bool {
	if dir == "" {
		return false
	}
	return pathExists(filepath.Join(dir, "go-tesec")) &&
		pathExists(filepath.Join(dir, "experiments")) &&
		pathExists(filepath.Join(dir, "syscall-gen"))
}

func findWorkspaceRoot() string {
	search := func(dir string) string {
		for {
			if isWorkspaceRoot(dir) {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return ""
			}
			dir = parent
		}
	}

	if dir := os.Getenv("WEBSHRINK_WORKSPACE_ROOT"); dir != "" {
		if root := search(dir); root != "" {
			return root
		}
	}

	if dir, err := os.Getwd(); err == nil {
		if root := search(dir); root != "" {
			return root
		}
	}

	if pwd := os.Getenv("PWD"); pwd != "" {
		if root := search(pwd); root != "" {
			return root
		}
	}

	if _, file, _, ok := runtime.Caller(0); ok {
		if root := search(filepath.Dir(file)); root != "" {
			return root
		}
	}

	return ""
}

func normalizeTraceSourcePath(filePath string) string {
	cleaned := filepath.Clean(filePath)
	if pathExists(cleaned) {
		return cleaned
	}

	repoRoot := findWorkspaceRoot()
	if repoRoot == "" {
		return cleaned
	}

	slashPath := filepath.ToSlash(cleaned)
	candidates := []string{}
	appendCandidate := func(relative string) {
		if relative == "" {
			return
		}
		candidates = append(candidates, filepath.Join(repoRoot, filepath.FromSlash(relative)))
	}

	if idx := strings.Index(slashPath, "/webshrink/"); idx != -1 {
		appendCandidate(slashPath[idx+len("/webshrink/"):])
	}
	for _, marker := range []string{"/experiments/", "/go-tesec/", "/syscall-gen/"} {
		if idx := strings.Index(slashPath, marker); idx != -1 {
			appendCandidate(strings.TrimPrefix(slashPath[idx:], "/"))
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if pathExists(candidate) {
			return candidate
		}
	}

	return cleaned
}

func loadDAGNodeKeys(graphSyscallFile string) map[string]struct{} {
	if graphSyscallFile == "" {
		return nil
	}

	data, err := os.ReadFile(graphSyscallFile)
	if err != nil {
		log.Printf("warn: failed to read graph syscall file %s: %v", graphSyscallFile, err)
		return nil
	}

	var nodes []DAGNodeJSON
	if err := json.Unmarshal(data, &nodes); err != nil {
		log.Printf("warn: failed to parse graph syscall file %s: %v", graphSyscallFile, err)
		return nil
	}

	keys := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if node.Key == "" {
			continue
		}
		keys[node.Key] = struct{}{}
	}
	return keys
}

func selectTraceAnchorIndex(stackKeys []string, matchedIndices []int, dagNodeKeys map[string]struct{}) int {
	if len(stackKeys) == 0 {
		return -1
	}

	// 没有 DAG 锚点时，退回当前行为：优先保留已匹配的 handler，
	// 否则保留离 os.StartProcess 最近的业务函数。
	if len(dagNodeKeys) == 0 {
		if len(matchedIndices) > 0 {
			return matchedIndices[0]
		}
		return 0
	}

	limit := len(stackKeys) - 1
	if len(matchedIndices) > 0 {
		// 只在当前请求 handler 之下选 anchor，避免把 macaron/http 外层框架帧拿来做 launch frame。
		limit = matchedIndices[0]
	}

	for i := 0; i <= limit; i++ {
		if _, ok := dagNodeKeys[stackKeys[i]]; ok {
			return i
		}
	}

	if len(matchedIndices) > 0 {
		return matchedIndices[0]
	}
	return 0
}

func selectTraceAnchor(stackFuncs []*ssa.Function, matchedIndices []int, dagNodeKeys map[string]struct{}) *ssa.Function {
	if len(stackFuncs) == 0 {
		return nil
	}

	stackKeys := make([]string, 0, len(stackFuncs))
	for _, fn := range stackFuncs {
		if fn == nil {
			stackKeys = append(stackKeys, "")
			continue
		}
		stackKeys = append(stackKeys, fn.String())
	}

	index := selectTraceAnchorIndex(stackKeys, matchedIndices, dagNodeKeys)
	if index < 0 || index >= len(stackFuncs) {
		return nil
	}
	return stackFuncs[index]
}

// ProcessStackFileLines 逐行处理日志 (逻辑保持不变)
func ProcessStackFileLines(mainPkg, filePath, sigTemp string, dagNodeKeys map[string]struct{}) (map[string][]*ssa.Function, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	mainPkg = canonicalMainPkgFromCache(mainPkg)

	sigMatcher, err := utils.NewSignatureMatcher(sigTemp)
	if err != nil {
		return nil, fmt.Errorf("invalid function signature pattern: %w", err)
	}

	scanner := bufio.NewScanner(file)
	const maxCapacity = 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	currentPid := ""
	var pendingFunc string // 状态机

	nameToSSAFunc := make(map[string]*ssa.Function)
	pidToHandlerFunc := make(map[string][]*ssa.Function)
	stackFuncs := make([]*ssa.Function, 0, 8)
	stackFuncSeen := make(map[string]struct{})
	stackFuncIndex := make(map[string]int)
	matchedIndices := make([]int, 0, 2)

	finalizeStack := func(pid string) {
		if pid == "" {
			return
		}
		if len(stackFuncs) == 0 {
			return
		}
		anchor := selectTraceAnchor(stackFuncs, matchedIndices, dagNodeKeys)
		if anchor == nil {
			return
		}
		pidToHandlerFunc[pid] = append(pidToHandlerFunc[pid], anchor)
		if len(matchedIndices) == 0 && anchor == stackFuncs[0] {
			// 如果当前 os.StartProcess 调用栈里没有直接出现 handler 签名，
			// 说明 subprocess 是在 handler 派生出的 goroutine/闭包里启动的。
			// 此时退回到离 StartProcess 最近的业务函数，后续再依赖 DAG 传播回 handler。
			fmt.Printf("PID: %s -> 未直接匹配 handler，回退到业务函数: %s\n", pid, anchor.String())
			return
		}
		fmt.Printf("PID: %s -> 归并锚点: %s\n", pid, anchor.String())
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "GOEXECSTACK") {
			finalizeStack(currentPid)
			currentPid = parsePid(line)
			pendingFunc = ""
			stackFuncs = stackFuncs[:0]
			stackFuncSeen = make(map[string]struct{})
			stackFuncIndex = make(map[string]int)
			matchedIndices = matchedIndices[:0]
			continue
		}

		if currentPid == "" {
			continue
		}

		// --- 状态机逻辑 ---
		if pendingFunc == "" {
			// 当前行是：函数名
			if isStdLib(line) {
				pendingFunc = "SKIP"
			} else {
				pendingFunc = line
			}
		} else {
			// 当前行是：文件路径
			if pendingFunc != "SKIP" {
				if _, exists := nameToSSAFunc[pendingFunc]; !exists {
					ssaFunc, err := getSSAFunction(mainPkg, pendingFunc, line)
					if err != nil || ssaFunc == nil {
						fmt.Printf("无法找到函数 %s 对应的 SSA 函数: %v\n", pendingFunc, err)
						pendingFunc = ""
						continue
					}
					nameToSSAFunc[pendingFunc] = ssaFunc
				}
				ssaFunc := nameToSSAFunc[pendingFunc]
				if _, exists := stackFuncSeen[ssaFunc.String()]; !exists {
					stackFuncSeen[ssaFunc.String()] = struct{}{}
					stackFuncIndex[ssaFunc.String()] = len(stackFuncs)
					stackFuncs = append(stackFuncs, ssaFunc)
				}
				currentIndex := stackFuncIndex[ssaFunc.String()]

				sig := GetFunctionSignature(ssaFunc)
				if sig == "" {
					pendingFunc = ""
					continue
				}
				if sigMatcher.Match(sig) {
					matchedIndices = append(matchedIndices, currentIndex)
				}

			}
			pendingFunc = ""
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	finalizeStack(currentPid)
	for pid, fns := range pidToHandlerFunc {
		for _, fn := range fns {
			fmt.Printf("PID: %s -> 处理函数: %s\n", pid, fn.String())
		}
	}

	return pidToHandlerFunc, nil
}

func getSSAFunction(mainPkg, funcName string, pathWithLine string) (*ssa.Function, error) {
	pkgPath, funcName := utils.ParseRuntimeNameWithMainPkg(funcName, mainPkg)
	if loadPathToProg[pkgPath] == nil {
		ensureProgramLoaded(pkgPath)
	}

	ssaFunc := utils.FindFunction(loadPathToProg[pkgPath], loadPathToPkgs[pkgPath], funcName)
	var err error
	if ssaFunc == nil {
		ssaFunc, err = findLoadedSSAFunction(pathWithLine, loadPathToProg[pkgPath], loadPathTossaPkgs[pkgPath])
		if err != nil {
			return nil, fmt.Errorf("function %s location lookup failed in package %s: %w", funcName, pkgPath, err)
		}
	}
	if ssaFunc == nil {
		fmt.Printf("函数 %s 在包 %s 中未找到，尝试通过路径和行号按需反查 SSA 函数...\n", funcName, pkgPath)
		ssaFunc, err = getSSAFunctionFallback(pathWithLine)
		if err != nil {
			return nil, fmt.Errorf("function %s not found in package %s: %w", funcName, pkgPath, err)
		}
	}
	return ssaFunc, nil
}

func findLoadedSSAFunction(pathWithLine string, prog *ssa.Program, ssaPkgs []*ssa.Package) (*ssa.Function, error) {
	if prog == nil {
		return nil, nil
	}

	filePath, line, err := parsePathLine(pathWithLine)
	if err != nil {
		return nil, err
	}

	for _, ssaPkg := range ssaPkgs {
		if ssaPkg == nil {
			continue
		}
		if fn := FindSSAFunctionOnDemand(prog, ssaPkg, filePath, line); fn != nil {
			return fn, nil
		}
	}

	return nil, nil
}

// 标准库根目录列表 (基于 Set 结构优化查询速度 O(1))
var stdLibRoots = map[string]struct{}{
	"archive": {}, "arena": {}, "bufio": {}, "builtin": {}, "bytes": {},
	"cmp": {}, "cmd": {}, "compress": {}, "container": {}, "context": {},
	"crypto": {}, "database": {}, "debug": {}, "embed": {}, "encoding": {},
	"errors": {}, "expvar": {}, "flag": {}, "fmt": {}, "go": {}, "hash": {},
	"html": {}, "image": {}, "index": {}, "internal": {}, "io": {},
	"iter": {}, "log": {}, "maps": {}, "math": {}, "mime": {}, "net": {},
	"os": {}, "path": {}, "plugin": {}, "reflect": {}, "regexp": {},
	"runtime": {}, "slices": {}, "sort": {}, "strconv": {}, "strings": {},
	"structs": {}, "sync": {}, "syscall": {}, "testing": {}, "text": {},
	"time": {}, "unicode": {}, "unique": {}, "unsafe": {}, "vendor": {},
	"weak": {},
}

// isStdLib 判断是否为标准库函数
func isStdLib(funcName string) bool {
	var pkgPath string
	firstDot := strings.Index(funcName, ".")
	firstSlash := strings.Index(funcName, "/")
	if firstSlash != -1 && firstDot != -1 && firstDot < firstSlash {
		// 有斜杠有点，且点在斜杠前面，说明是域名开头的包名, 非标准库
		return false
	}
	if firstDot == -1 {
		// 没有点，说明不是标准库
		println("没有点，非标准库:", funcName)
		return false
	}
	pkgPath = funcName[:firstDot]

	parts := strings.SplitN(pkgPath, "/", 2)
	if len(parts) == 0 {
		return false
	}
	root := parts[0]
	_, isStd := stdLibRoots[root]
	return isStd
}

// parsePid 解析形如 "GOEXECSTACK ts=1768985864933373540 pid=606960" 的行，返回 pid 字符串
func parsePid(line string) string {
	const key = "pid="
	idx := strings.Index(line, key)
	if idx == -1 {
		panic("调用栈日志文件存在错误，无pid")
	}
	pidVal := line[idx+len(key):]
	return strings.TrimSpace(pidVal)
}

// pathWithLine:  本地修正后的文件路径和行号 (例如 "/Users/me/project/main.go:42")
func getSSAFunctionFallback(pathWithLine string) (*ssa.Function, error) {
	// 解析路径
	filePath, line, err := parsePathLine(pathWithLine)
	if err != nil {
		return nil, err
	}

	// 加载并构建 SSA (保留原逻辑，通过路径反查包)
	prog, pkg, err := loadAndBuild(filePath)
	if err != nil {
		return nil, err
	}

	ssaFunc := FindSSAFunctionOnDemand(prog, pkg, filePath, line)

	if ssaFunc == nil {
		return nil, fmt.Errorf("no function found at %s covering line %d", filePath, line)
	}

	return ssaFunc, nil
}

func resolveLoadTargetForFile(absFilePath string) (dir string, pattern string) {
	dir = filepath.Dir(absFilePath)
	pattern = "."

	checkStdlibRoot := func(srcRoot string) bool {
		if srcRoot == "" {
			return false
		}
		rel, err := filepath.Rel(srcRoot, absFilePath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return false
		}
		pkgDir := filepath.Dir(rel)
		if pkgDir == "." || pkgDir == "" {
			return false
		}
		returnPath := filepath.ToSlash(pkgDir)
		dir = srcRoot
		pattern = returnPath
		return true
	}

	if goroot := os.Getenv("GOROOT"); goroot != "" {
		if checkStdlibRoot(filepath.Join(goroot, "src")) {
			return dir, pattern
		}
	}

	if inferred := inferStdlibSrcRootFromPath(absFilePath); inferred != "" && checkStdlibRoot(inferred) {
		return dir, pattern
	}

	if checkStdlibRoot(filepath.Join(runtime.GOROOT(), "src")) {
		return dir, pattern
	}

	return dir, pattern
}

func inferStdlibSrcRootFromPath(absFilePath string) string {
	dir := filepath.Clean(filepath.Dir(absFilePath))
	for {
		if filepath.Base(dir) == "src" &&
			pathExists(filepath.Join(dir, "runtime")) &&
			pathExists(filepath.Join(dir, "sync")) {
			rel, err := filepath.Rel(dir, absFilePath)
			if err == nil && rel != "" && !strings.HasPrefix(rel, "..") {
				first := strings.Split(filepath.ToSlash(rel), "/")[0]
				if first != "" && !strings.Contains(first, ".") {
					return dir
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// loadAndBuild 加载包并构建 SSA
// 策略：切换工作目录到目标文件所在的文件夹，然后加载当前目录包 (".")
func loadAndBuild(filePath string) (*ssa.Program, *ssa.Package, error) {
	// 1. 路径标准化
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid file path: %w", err)
	}

	if _, err := os.Stat(absFilePath); err != nil {
		return nil, nil, fmt.Errorf("file not found: %s", absFilePath)
	}

	// 2. 获取加载根目录与 pattern。对于 stdlib 文件，必须恢复成真实 import path
	// （例如 sync、internal/sync），否则在带 -modfile 的主模块上下文里用 "."
	// 加载会被错误解释成主模块内包路径。
	dir, pattern := resolveLoadTargetForFile(absFilePath)
	cacheKey := dir + "\x00" + pattern
	if cached, ok := ssaLookupCache[cacheKey]; ok {
		return cached.prog, cached.pkg, nil
	}

	// 3. 配置加载器
	cfg := &packages.Config{
		// 关键点：将加载器的工作目录切换到目标文件所在目录
		Dir: dir,

		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		BuildFlags: BuildFlags,
		Tests:      false,
	}

	// 4. 加载目标包。stdlib 文件使用真实 import path，其余场景保持 "."
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("packages load error: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, nil, fmt.Errorf("packages contain errors")
	}
	if len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("no package found in directory: %s", dir)
	}

	// 5. 构建 SSA
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	// 6. 查找目标 SSA 包 (保留原有查找逻辑)
	var targetSSAPkg *ssa.Package
	var targetPkgID string

	// 优先找主包，其次找测试包
	for i, pkg := range pkgs {
		for _, f := range pkg.GoFiles {
			fAbs, _ := filepath.Abs(f)
			if fAbs == absFilePath {
				targetPkgID = pkg.PkgPath
				if !strings.HasSuffix(pkg.ID, ".test") {
					goto FoundID
				}
			}
		}
		if i == len(pkgs)-1 && targetPkgID == "" {
			// fallback logic
		}
	}

FoundID:
	if targetPkgID == "" {
		if len(ssaPkgs) > 0 {
			targetSSAPkg = ssaPkgs[0]
		}
	} else {
		for _, sp := range ssaPkgs {
			if sp != nil && sp.Pkg.Path() == targetPkgID {
				targetSSAPkg = sp
				break
			}
			if sp != nil && strings.TrimSuffix(sp.Pkg.Path(), "_test") == targetPkgID {
				targetSSAPkg = sp
				break
			}
		}
	}

	if targetSSAPkg == nil && len(ssaPkgs) > 0 {
		targetSSAPkg = ssaPkgs[0] // Fallback
	}

	if targetSSAPkg == nil {
		return nil, nil, fmt.Errorf("could not locate ssa package for %s", absFilePath)
	}

	ssaLookupCache[cacheKey] = ssaLookupCacheEntry{
		prog: prog,
		pkg:  targetSSAPkg,
	}

	return prog, targetSSAPkg, nil
}

// 给定 Prog, Pkg, 文件绝对路径, 行号，直接返回 SSA Function
func FindSSAFunctionOnDemand(prog *ssa.Program, pkg *ssa.Package, filePath string, line int) *ssa.Function {
	candidates := FindSSAFunctionsCoveringLine(prog, pkg, filePath, line)
	return chooseBestSSAFunction(candidates)
}

func FindSSAFunctionsCoveringLine(prog *ssa.Program, pkg *ssa.Package, filePath string, line int) []*ssa.Function {
	absFilePath, err := filepath.Abs(filePath)
	if err == nil {
		filePath = absFilePath
	}

	// 定义一个检查函数：判断某 SSA 函数是否覆盖了目标行
	check := func(fn *ssa.Function) bool {
		// 必须要有源码信息
		if fn.Syntax() == nil {
			return false
		}

		// 1. 快速检查：利用 Fset 获取位置
		// 由于我们只针对单个包的几十个函数调用，这里使用 Position 开销可控且安全
		pos := prog.Fset.Position(fn.Pos())

		// 路径必须完全一致
		if filepath.Clean(pos.Filename) != filepath.Clean(filePath) {
			return false
		}

		// 2. 检查起始行
		if line < pos.Line {
			return false
		}

		// 3. 检查结束行
		end := prog.Fset.Position(fn.Syntax().End())
		if line > end.Line {
			return false
		}

		return true
	}

	seen := make(map[string]bool)
	var candidates []*ssa.Function
	addCandidate := func(fn *ssa.Function) {
		if fn == nil {
			return
		}
		specific := drillDownToSpecificClosure(prog, fn, filePath, line)
		if specific == nil {
			return
		}
		key := specific.String()
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, specific)
	}

	// 1. 遍历顶级函数 (Func) 和 类型 (Type)
	for _, member := range pkg.Members {
		switch m := member.(type) {
		case *ssa.Function:
			// 顶级函数
			if check(m) {
				addCandidate(m)
			}

		case *ssa.Type:
			// 类型方法：遍历该类型的所有方法
			// 注意：方法必须定义在目标 filepath 文件中，check() 会负责判断
			ptrType := types.NewPointer(m.Type()) // 此处需要 import "go/types"
			mset := prog.MethodSets.MethodSet(ptrType)

			for i := 0; i < mset.Len(); i++ {
				sel := mset.At(i)
				// 获取方法的 SSA 函数对象
				fn := prog.MethodValue(sel)

				// 关键：只检查属于当前包的方法 (避免嵌入字段引入的其他包方法)
				if fn != nil && fn.Pkg == pkg {
					if check(fn) {
						addCandidate(fn)
					}
				}
			}
		}
	}

	// 2. 再遍历包内所有函数，补上实例化泛型闭包等不会出现在 Members 中的候选。
	for fn := range ssautil.AllFunctions(prog) {
		if fn == nil || fn.Pkg != pkg {
			continue
		}
		if check(fn) {
			addCandidate(fn)
		}
	}

	// 3. 特殊处理 init 函数
	// init 函数也是 ssa.Function，通常可以通过 pkg.Func("init") 获取
	// 注意：pkg.Members 中可能不直接包含合成的 init
	if initFn := pkg.Func("init"); initFn != nil {
		if check(initFn) {
			addCandidate(initFn)
		}
	}

	return candidates
}

func chooseBestSSAFunction(candidates []*ssa.Function) *ssa.Function {
	var best *ssa.Function
	bestScore := -1

	score := func(fn *ssa.Function) int {
		if fn == nil {
			return -1
		}
		name := fn.String()
		s := strings.Count(name, "$") * 100
		if strings.Contains(name, "[") {
			s += 20
		}
		if fn.Parent() != nil {
			s += 10
		}
		s += len(name)
		return s
	}

	for _, fn := range candidates {
		current := score(fn)
		if current > bestScore {
			best = fn
			bestScore = current
		}
	}

	return best
}

// drillDownToSpecificClosure 递归查找包含目标行的最内层闭包
func drillDownToSpecificClosure(prog *ssa.Program, parent *ssa.Function, filePath string, line int) *ssa.Function {
	// 假设 parent 已经覆盖了 line，我们看它的子函数（闭包）里有没有也能覆盖 line 的
	for _, anon := range parent.AnonFuncs {
		if anon.Syntax() == nil {
			continue
		}

		pos := prog.Fset.Position(anon.Pos())

		// 优化：只有同文件才继续
		if pos.Filename == filePath {
			end := prog.Fset.Position(anon.Syntax().End())
			if line >= pos.Line && line <= end.Line {
				// 找到了一个更具体的子函数！递归进入
				return drillDownToSpecificClosure(prog, anon, filePath, line)
			}
		}
	}

	// 如果所有子函数都不匹配，那目前这个 parent 就是最具体的函数
	return parent
}

func parsePathLine(s string) (string, int, error) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return "", 0, fmt.Errorf("invalid format path:line")
	}
	line, err := strconv.Atoi(s[lastColon+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid line number")
	}
	return normalizeTraceSourcePath(s[:lastColon]), line, nil
}

func GetFunctionSignature(fn *ssa.Function) string {
	if fn == nil || fn.Signature == nil {
		fmt.Println("函数为空或没有签名")
		return ""
	}

	sig := fn.Signature    // 类型是 *types.Signature
	params := sig.Params() // 获取参数元组 *types.Tuple

	sigString := "("

	// --- 遍历参数 ---
	for i := 0; i < params.Len(); i++ {
		paramVar := params.At(i)
		sigString += paramVar.Type().String()
		if i < params.Len()-1 {
			sigString += ", "
		}
	}
	sigString += ")"
	sigString += " -> ["
	// --- 遍历返回值 (如果有需要) ---
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		resVar := results.At(i)
		sigString += resVar.Type().String()
		if i < results.Len()-1 {
			sigString += ", "
		}
	}
	sigString += "]"
	return sigString
}

// buildParentMap 从 sysdig 日志中构建子进程→父进程映射
func buildParentMap(sysdigLogPath string) map[int]int {
	file, err := os.Open(sysdigLogPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	parentMap := make(map[int]int)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 10*1024*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		rawBytes := scanner.Bytes()
		if len(rawBytes) == 0 {
			continue
		}
		event, err := utils.DecodeSysdigProcessEvent(rawBytes)
		if err != nil {
			continue
		}
		if event.PPid != 0 && event.Pid != 0 && event.Pid != event.PPid {
			parentMap[event.Pid] = event.PPid
		}
	}
	return parentMap
}

// findAncestorHandler 从 pid 沿进程树向上查找最近的在 tracePIDs 中的祖先
func findAncestorHandler(pid int, parentMap map[int]int, tracePIDs map[int]bool) int {
	current := pid
	for i := 0; i < 50; i++ { // 防止无限循环
		if tracePIDs[current] {
			return current
		}
		parent, ok := parentMap[current]
		if !ok || parent == 0 {
			return -1
		}
		current = parent
	}
	return -1
}

func buildProcessGraph(sysdigLogPath string) (map[int]int, map[int]procMeta) {
	file, err := os.Open(sysdigLogPath)
	if err != nil {
		return nil, nil
	}
	defer file.Close()

	parentMap := make(map[int]int)
	procMetaByPID := make(map[int]procMeta)
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 10*1024*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		rawBytes := scanner.Bytes()
		if len(rawBytes) == 0 {
			continue
		}
		event, err := utils.DecodeSysdigProcessEvent(rawBytes)
		if err != nil {
			continue
		}
		if event.Pid == 0 {
			continue
		}
		if event.PPid != 0 && event.Pid != event.PPid {
			parentMap[event.Pid] = event.PPid
		}
		procMetaByPID[event.Pid] = procMeta{
			Pid:     event.Pid,
			PPid:    event.PPid,
			Name:    event.Name,
			ExePath: event.ExePath,
			Cmdline: event.Cmdline,
		}
	}

	return parentMap, procMetaByPID
}

func sameBinaryProc(a, b procMeta) bool {
	if a.ExePath != "" && b.ExePath != "" {
		if filepath.Clean(a.ExePath) == filepath.Clean(b.ExePath) {
			return true
		}
		if filepath.Base(a.ExePath) != "" && filepath.Base(a.ExePath) == filepath.Base(b.ExePath) {
			return true
		}
	}
	return a.ExePath == "" && b.ExePath == "" && a.Name != "" && a.Name == b.Name
}

func isPathWithinRoot(path string, root string) bool {
	if path == "" || root == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func isWorkspaceBinary(exePath string, workspaceRoot string) bool {
	return exePath != "" && workspaceRoot != "" && isPathWithinRoot(exePath, workspaceRoot)
}

func splitAlphaNumTokens(arg string) []string {
	return strings.FieldsFunc(strings.ToLower(arg), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func tokenizeSubcommandArgs(cmdline string) []string {
	fields := strings.Fields(cmdline)
	if len(fields) <= 1 {
		return nil
	}

	seen := make(map[string]struct{})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields[1:] {
		if field == "" || strings.HasPrefix(field, "-") {
			continue
		}
		if strings.Contains(field, "/") || strings.Contains(field, "\\") || strings.Contains(field, ".") {
			continue
		}
		for _, token := range splitAlphaNumTokens(field) {
			if len(token) < 2 {
				continue
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func normalizeAlphaNumLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func matchUniqueSelfReexecTarget(tokens []string, dagNodeKeys map[string]struct{}) string {
	if len(tokens) == 0 || len(dagNodeKeys) == 0 {
		return ""
	}

	match := ""
	for key := range dagNodeKeys {
		normKey := normalizeAlphaNumLower(key)
		ok := true
		for _, token := range tokens {
			if !strings.Contains(normKey, token) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if match != "" && match != key {
			return ""
		}
		match = key
	}
	return match
}

func selectSelfReexecRuntimeTarget(pid, traceAncestor int, parentMap map[int]int, procMetaByPID map[int]procMeta, dagNodeKeys map[string]struct{}) string {
	if pid == traceAncestor || len(dagNodeKeys) == 0 {
		return ""
	}
	ancestorMeta, ok := procMetaByPID[traceAncestor]
	if !ok {
		return ""
	}
	workspaceRoot := findWorkspaceRoot()
	fallback := ""
	debugSelfReexec := os.Getenv("WSHRINK_DEBUG_SELFREEXEC") != ""

	current := pid
	for i := 0; i < 50 && current != 0 && current != traceAncestor; i++ {
		meta, ok := procMetaByPID[current]
		if ok {
			tokens := tokenizeSubcommandArgs(meta.Cmdline)
			if debugSelfReexec && len(tokens) > 0 {
				fmt.Printf("DEBUG self-reexec pid=%d trace_ancestor=%d current=%d exe=%s workspace=%s in_workspace=%v tokens=%v\n",
					pid, traceAncestor, current, meta.ExePath, workspaceRoot, isWorkspaceBinary(meta.ExePath, workspaceRoot), tokens)
			}
			if isWorkspaceBinary(meta.ExePath, workspaceRoot) {
				if target := matchUniqueSelfReexecTarget(tokens, dagNodeKeys); target != "" {
					return target
				}
			}
			if fallback == "" && sameBinaryProc(meta, ancestorMeta) {
				if target := matchUniqueSelfReexecTarget(tokens, dagNodeKeys); target != "" {
					fallback = target
				}
			}
			if meta.PPid == traceAncestor && sameBinaryProc(meta, ancestorMeta) {
				if target := matchUniqueSelfReexecTarget(tokens, dagNodeKeys); target != "" {
					return target
				}
			}
		}
		parent, ok := parentMap[current]
		if !ok || parent == 0 || parent == current {
			break
		}
		current = parent
	}
	return fallback
}

func lookupRuntimeFunction(mainPkg, runtimeName string) *ssa.Function {
	mainPkg = canonicalMainPkgFromCache(mainPkg)
	pkgPath, funcName := utils.ParseRuntimeNameWithMainPkg(runtimeName, mainPkg)
	if loadPathToProg[pkgPath] == nil {
		ensureProgramLoaded(pkgPath)
	}
	return utils.FindFunction(loadPathToProg[pkgPath], loadPathToPkgs[pkgPath], funcName)
}

func addSyscallNamesToResult(resMap map[string][]int, fnKey string, syscalls []string, invertedSyscallMap map[string]int) {
	if fnKey == "" || len(syscalls) == 0 {
		return
	}

	syscallNums := make([]int, 0, len(syscalls))
	for _, sc := range syscalls {
		if num, ok := invertedSyscallMap[sc]; ok {
			syscallNums = append(syscallNums, num)
		} else {
			fmt.Printf("警告: 未知系统调用名称 %s\n", sc)
		}
	}
	if len(syscallNums) == 0 {
		return
	}

	if existing, ok := resMap[fnKey]; ok {
		combined := append(existing, syscallNums...)
		unique := make([]int, 0, len(combined))
		seen := make(map[int]struct{})
		for _, num := range combined {
			if _, found := seen[num]; !found {
				seen[num] = struct{}{}
				unique = append(unique, num)
			}
		}
		slices.Sort(unique)
		resMap[fnKey] = unique
		return
	}

	slices.Sort(syscallNums)
	resMap[fnKey] = syscallNums
}

// GetSubProcessSyscall 获取子进程的系统调用映射
// traceLog: 调用栈日志文件路径
// sysdigLog: 系统调用日志文件路径
// funcSig: 目标处理函数签名, 形如 "(*gogs.io/gogs/internal/context.Context) -> []" // (param type, param type) -> [return type, return type]
func GetSubProcessSyscall(mainPkg, traceLog, sysdigLog, funcSig, graphSyscallFile string) map[string][]int {
	dagNodeKeys := loadDAGNodeKeys(graphSyscallFile)
	pidToFuncs, err := ProcessStackFileLines(mainPkg, traceLog, funcSig, dagNodeKeys)
	if err != nil {
		fmt.Printf("处理调用栈日志文件时出错: %v\n", err)
		return nil
	}
	pidToSyscalls, err := utils.LoadSysdigSyscallsFromFile(sysdigLog)
	if err != nil {
		fmt.Printf("加载系统调用日志文件时出错: %v\n", err)
		return nil
	}

	// 构建 trace PID 集合和进程树，用于深层子进程追溯
	tracePIDs := make(map[int]bool)
	for pidStr := range pidToFuncs {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			tracePIDs[pid] = true
		}
	}
	parentMap, procMetaByPID := buildProcessGraph(sysdigLog)
	if parentMap == nil {
		parentMap = buildParentMap(sysdigLog)
	}
	// 将深层子进程的 syscall 合并到其最近的 trace 祖先 handler
	mergedSyscalls := make(map[string][]string)
	reentrySyscalls := make(map[string][]string)
	for pidStr, syscalls := range pidToSyscalls {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		ancestor := findAncestorHandler(pid, parentMap, tracePIDs)
		if ancestor < 0 {
			continue
		}
		if runtimeTarget := selectSelfReexecRuntimeTarget(pid, ancestor, parentMap, procMetaByPID, dagNodeKeys); runtimeTarget != "" {
			if fn := lookupRuntimeFunction(mainPkg, runtimeTarget); fn != nil {
				fmt.Printf("PID: %d -> self-reexec anchor: %s\n", pid, fn.String())
				reentrySyscalls[fn.String()] = append(reentrySyscalls[fn.String()], syscalls...)
				continue
			}
		}
		ancestorStr := strconv.Itoa(ancestor)
		if existing, ok := mergedSyscalls[ancestorStr]; ok {
			mergedSyscalls[ancestorStr] = append(existing, syscalls...)
		} else {
			mergedSyscalls[ancestorStr] = syscalls
		}
	}
	// 合并后的 syscall 去重
	for pidStr, syscalls := range mergedSyscalls {
		existing, ok := pidToSyscalls[pidStr]
		if !ok {
			pidToSyscalls[pidStr] = syscalls
			continue
		}
		seen := make(map[string]struct{})
		for _, sc := range existing {
			seen[sc] = struct{}{}
		}
		for _, sc := range syscalls {
			if _, ok := seen[sc]; !ok {
				existing = append(existing, sc)
				seen[sc] = struct{}{}
			}
		}
		pidToSyscalls[pidStr] = existing
	}

	var resMap map[string][]int = make(map[string][]int)
	syscallMap, err := utils.LoadSyscallMap()
	if err != nil {
		fmt.Printf("加载系统调用映射时出错: %v\n", err)
		return nil
	}
	invertedSyscallMap := make(map[string]int)
	for num, name := range syscallMap {
		invertedSyscallMap[name] = num
	}
	//  prlimit -> prlimit64
	//  procexit -> 忽略
	//  switch -> 忽略
	invertedSyscallMap["prlimit"] = invertedSyscallMap["prlimit64"]

	// 输出结果
	for pid, fns := range pidToFuncs {
		for _, fn := range fns {
			syscalls, exists := pidToSyscalls[pid]
			if !exists {
				fmt.Printf("PID: %s\n处理函数: %s\n系统调用: 无记录\n\n", pid, fn.String())
				continue
			}
			addSyscallNamesToResult(resMap, fn.String(), syscalls, invertedSyscallMap)
		}
	}
	for fnKey, syscalls := range reentrySyscalls {
		addSyscallNamesToResult(resMap, fnKey, syscalls, invertedSyscallMap)
	}
	// 打印resMap到文件
	fileOut, err := os.Create("./tmp/resMap.json")
	if err != nil {
		return nil
	}
	defer fileOut.Close()

	encoder := json.NewEncoder(fileOut)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(resMap); err != nil {
		return nil
	}
	return resMap
}
