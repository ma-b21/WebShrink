package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"linkname-analyzer/types"
)

func main() {
	var (
		outputFile string
		verbose    bool
	)

	flag.StringVar(&outputFile, "output", "linkname_mapping.json", "输出的 JSON 文件路径")
	flag.BoolVar(&verbose, "verbose", false, "显示详细信息")
	flag.Parse()

	fmt.Printf("Go 版本: %s\n", runtime.Version())
	fmt.Println("开始分析 Go 标准库...")

	// 加载所有标准库包
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
	}

	fmt.Println("工作路径：", cfg.Dir)
	fmt.Println("正在加载标准库包...")
	pkgs, err := packages.Load(cfg, "std", "vendor/golang.org/x/...")
	for _, pkg := range pkgs {
		// pkg.GoFiles - Go 源文件
		// pkg.CgoFiles - Cgo 文件
		// pkg.OtherFiles - 其他文件（包括 .s 汇编）
		
		for _, asmFile := range pkg.OtherFiles {
			if strings.HasSuffix(asmFile, ".s") {
				fmt.Printf("汇编文件: %s (包: %s)\n", asmFile, pkg.PkgPath)
			}
		}
	}
	if err != nil {
		log.Fatalf("加载标准库失败: %v", err)
	}

	if packages.PrintErrors(pkgs) > 0 {
		log.Fatal("标准库中存在错误")
	}

	fmt.Printf("已加载 %d 个标准库包\n", len(pkgs))

	// 构建 SSA
	fmt.Println("构建 SSA 表示...")
	prog, _ := ssautil.AllPackages(pkgs, 0)
	prog.Build()

	// 提取所有 linkname 信息
	fmt.Println("提取 linkname 注释...")
	entries := extractLinknames(pkgs, prog, verbose)

	fmt.Println("合并 linkname 链...")
	entries = mergeTransitiveLinknames(entries, verbose)

	fmt.Printf("\n找到 %d 个 go:linkname 声明\n", len(entries))

	// 保存为 JSON
	err = saveJSON(entries, outputFile)
	if err != nil {
		log.Fatalf("保存 JSON 文件失败: %v", err)
	}

	fmt.Printf("映射表已保存到: %s\n", outputFile)

	// 统计信息
	// printStatistics(entries)
}

// extractLinknames 从所有包中提取 linkname 信息
func extractLinknames(pkgs []*packages.Package, prog *ssa.Program, verbose bool) []types.LinknameEntry {
	var entries []types.LinknameEntry
	seen := make(map[string]bool) // 去重

	for _, pkg := range pkgs {
		if pkg.Syntax == nil {
			continue
		}

		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				funcDecl, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}

				// 查找 //go:linkname 注释
				linkname := extractLinknameFromFunc(funcDecl)
				if linkname == nil {
					continue
				}

				// 处理 linkname，识别模式并获取声明和实现
				entry := processLinkname(pkg, ssaPkg, prog, pkgs, funcDecl, linkname, verbose)
				if entry == nil {
					continue
				}

				// 去重
				if entry.DeclFunc == entry.ImplFunc {
					continue
				}
				key := entry.DeclFunc + " -> " + entry.ImplFunc
				if seen[key] {
					continue
				}
				seen[key] = true

				entries = append(entries, *entry)

				if verbose {
					fmt.Printf("[%s] %s -> %s (%s:%d) [%s]%s\n",
						entry.Mode, entry.DeclFunc, entry.ImplFunc,
						entry.SourceFile, entry.Line, entry.Status,
						func() string {
							if entry.IsAsm {
								return " [ASM]"
							}
							return ""
						}())
				}
			}
		}
	}

	return entries
}

// extractLinknameFromFunc 从函数声明中提取 linkname 信息
func extractLinknameFromFunc(funcDecl *ast.FuncDecl) *types.LinknameInfo {
	if funcDecl.Doc == nil {
		return nil
	}

	for _, comment := range funcDecl.Doc.List {
		text := comment.Text
		if !strings.HasPrefix(text, "//go:linkname ") {
			continue
		}

		// 解析: //go:linkname localname [targetname]
		parts := strings.Fields(text)
		if len(parts) < 2 {
			continue
		}

		info := &types.LinknameInfo{
			LocalName: parts[1],
		}

		// targetname 可能不存在（只有 localname 的情况）
		if len(parts) >= 3 {
			info.TargetName = parts[2]
		}

		return info
	}

	return nil
}

// processLinkname 处理 linkname 注释，识别三种模式并返回映射条目
func processLinkname(
	pkg *packages.Package,
	ssaPkg *ssa.Package,
	prog *ssa.Program,
	allPkgs []*packages.Package,
	funcDecl *ast.FuncDecl,
	linkname *types.LinknameInfo,
	verbose bool,
) *types.LinknameEntry {

	currentFuncName := funcDecl.Name.Name
	hasBody := funcDecl.Body != nil

	var declFunc, implFunc *ssa.Function
	var declName, implName string
	var mode string
	var status string
	var isAsm bool

	// 如果没有 TargetName，说明是特殊情况（只导出符号，不重定向）
	if linkname.TargetName == "" {
		if verbose {
			fmt.Printf("  跳过: %s (只有 localname，无 targetname)\n", linkname.LocalName)
		}
		return nil
	}

	if linkname.LocalName == currentFuncName {
		// 情况 A: LocalName 就是当前函数名

		currentFunc := findFunctionInPackage(ssaPkg, funcDecl)

		if hasBody {
			// 模式 3: 导出型
			// 当前函数有实现，导出给另一个包用（TargetName 是外部声明）
			mode = "export"
			implFunc = currentFunc
			if implFunc != nil {
				implName = implFunc.String()
			} else {
				implName = fmt.Sprintf("%s.%s", pkg.PkgPath, currentFuncName)
			}

			// 去目标包找声明
			declFunc = findFunctionByName(prog, allPkgs, linkname.TargetName)
			declName = linkname.TargetName

			if declFunc != nil {
				status = "complete"
				// 检查声明函数是否有实现（通常导出型的目标是声明）
				if len(declFunc.Blocks) == 0 {
					isAsm = false // 当前函数有实现，不是汇编
				}
			} else {
				status = "decl_missing"
			}

		} else {
			// 模式 1: 导入型
			// 当前函数是声明，要从另一个包导入实现
			mode = "import"
			declFunc = currentFunc
			if declFunc != nil {
				declName = declFunc.String()
			} else {
				declName = fmt.Sprintf("%s.%s", pkg.PkgPath, currentFuncName)
			}

			// 去目标包找实现
			implFunc = findFunctionByName(prog, allPkgs, linkname.TargetName)
			implName = linkname.TargetName

			if implFunc != nil {
				status = "complete"
				implName = implFunc.String() // 使用 SSA 的完整名称
				
				// 检查实现函数是否有 Go 函数体
				if len(implFunc.Blocks) == 0 {
					// 没有基本块 = 没有 Go 实现，可能是汇编
					isAsm = true
				}
			} else {
				status = "impl_missing"
				isAsm = true // 找不到 SSA，肯定是汇编或外部实现
			}
		}

	} else {
		// 情况 B: LocalName 不是当前函数名
		// 模式 2: 桥接型
		// 当前函数是实现（通常是方法），LocalName 是桥接函数
		mode = "bridge"

		// 当前函数是实现
		implFunc = findFunctionInPackage(ssaPkg, funcDecl)
		implName = linkname.TargetName // 使用 TargetName 作为实现的完整名称

		// 如果能找到实际的 SSA，用 SSA 的名字
		if implFunc != nil {
			implName = implFunc.String()
			// 桥接模式下，当前函数就是实现，检查是否有函数体
			if len(implFunc.Blocks) == 0 {
				isAsm = true
			}
		}

		// LocalName 是桥接函数（应该在同一个包中）
		declFunc = ssaPkg.Func(linkname.LocalName)
		if declFunc != nil {
			declName = declFunc.String()
			status = "complete"
		} else {
			// 桥接函数可能找不到（可能只是个占位符）
			declName = fmt.Sprintf("%s.%s", pkg.PkgPath, linkname.LocalName)
			status = "decl_missing"
		}
	}

	entry := &types.LinknameEntry{
		DeclFunc:   declName,
		ImplFunc:   implName,
		DeclPkg:    extractPackagePath(declName),
		ImplPkg:    extractPackagePath(implName),
		SourceFile: prog.Fset.Position(funcDecl.Pos()).Filename,
		Line:       prog.Fset.Position(funcDecl.Pos()).Line,
		Mode:       mode,
		Status:     status,
		IsAsm:      isAsm,
	}

	return entry
}

// findFunctionInPackage 在指定包中查找函数的 SSA 表示
func findFunctionInPackage(pkg *ssa.Package, funcDecl *ast.FuncDecl) *ssa.Function {
	funcName := funcDecl.Name.Name

	// 包级别函数
	if funcDecl.Recv == nil {
		if fn := pkg.Func(funcName); fn != nil {
			return fn
		}

		// 在所有成员中查找
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if fn.Name() == funcName {
					return fn
				}
			}
		}
	} else {
		// 方法：需要查找对应类型的方法
		for _, member := range pkg.Members {
			if tp, ok := member.(*ssa.Type); ok {
				// 查找值方法和指针方法
				mset := pkg.Prog.MethodSets.MethodSet(tp.Type())
				for i := 0; i < mset.Len(); i++ {
					method := pkg.Prog.MethodValue(mset.At(i))
					if method != nil && method.Name() == funcName {
						return method
					}
				}
			}
		}
	}

	return nil
}

// findFunctionByName 在所有包中按完全限定名查找函数
func findFunctionByName(prog *ssa.Program, pkgs []*packages.Package, fullName string) *ssa.Function {
	// 解析完全限定名
	// 可能的格式:
	// 1. package.FuncName
	// 2. package.(*Type).Method
	// 3. package.(Type).Method

	// 提取包路径
	var pkgPath string
	var funcName string

	// 处理方法的情况: package.(*Type).Method
	if strings.Contains(fullName, "(") {
		parenIdx := strings.Index(fullName, "(")
		pkgPath = fullName[:parenIdx]
		// 去掉末尾的点
		pkgPath = strings.TrimSuffix(pkgPath, ".")

		lastDotIdx := strings.LastIndex(fullName, ".")
		if lastDotIdx > parenIdx {
			funcName = fullName[lastDotIdx+1:]
		}
	} else {
		// 包级别函数: package.FuncName
		lastDotIdx := strings.LastIndex(fullName, ".")
		if lastDotIdx == -1 {
			return nil
		}
		pkgPath = fullName[:lastDotIdx]
		funcName = fullName[lastDotIdx+1:]
	}

	// 查找对应的包
	for _, pkg := range pkgs {
		if pkg.PkgPath != pkgPath {
			continue
		}

		ssaPkg := prog.Package(pkg.Types)
		if ssaPkg == nil {
			continue
		}

		// 查找包级别函数
		if fn := ssaPkg.Func(funcName); fn != nil {
			return fn
		}

		// 查找方法和其他成员
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if fn.String() == fullName || fn.Name() == funcName {
					return fn
				}
			}

			// 查找类型的方法
			if tp, ok := member.(*ssa.Type); ok {
				mset := prog.MethodSets.MethodSet(tp.Type())
				for i := 0; i < mset.Len(); i++ {
					method := prog.MethodValue(mset.At(i))
					if method != nil {
						if method.String() == fullName || method.Name() == funcName {
							return method
						}
					}
				}
			}
		}
	}

	return nil
}

// extractPackagePath 从完全限定名中提取包路径
func extractPackagePath(fullName string) string {
	// 处理: package.func 或 package.(*Type).method
	if strings.Contains(fullName, "(") {
		parenIdx := strings.Index(fullName, "(")
		pkgPart := fullName[:parenIdx]
		return strings.TrimSuffix(pkgPart, ".")
	}

	lastDot := strings.LastIndex(fullName, ".")
	if lastDot == -1 {
		return ""
	}

	return fullName[:lastDot]
}

// saveJSON 将映射表保存为 JSON 文件
func saveJSON(entries []types.LinknameEntry, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(entries)
}

// printStatistics 打印统计信息
func printStatistics(entries []types.LinknameEntry) {
	modeCount := make(map[string]int)
	statusCount := make(map[string]int)
	pkgCount := make(map[string]int)
	asmCount := 0

	for _, entry := range entries {
		modeCount[entry.Mode]++
		statusCount[entry.Status]++
		pkgCount[entry.DeclPkg]++
		if entry.IsAsm {
			asmCount++
		}
	}

	fmt.Println("\n=== 按模式统计 ===")
	for _, mode := range []string{"import", "export", "bridge"} {
		if count, ok := modeCount[mode]; ok {
			fmt.Printf("  %s: %d\n", mode, count)
		}
	}

	fmt.Println("\n=== 按状态统计 ===")
	for _, status := range []string{"complete", "impl_missing", "decl_missing"} {
		if count, ok := statusCount[status]; ok {
			fmt.Printf("  %s: %d\n", status, count)
		}
	}

	fmt.Printf("\n=== 汇编实现统计 ===\n")
	fmt.Printf("  汇编实现: %d (%.1f%%)\n", asmCount, float64(asmCount)*100/float64(len(entries)))
	fmt.Printf("  Go 实现: %d (%.1f%%)\n", len(entries)-asmCount, float64(len(entries)-asmCount)*100/float64(len(entries)))

	fmt.Println("\n=== 按声明包统计 (Top 10) ===")
	type pkgStat struct {
		pkg   string
		count int
	}
	var stats []pkgStat
	for pkg, count := range pkgCount {
		stats = append(stats, pkgStat{pkg, count})
	}

	// 按数量排序
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].count > stats[j].count
	})

	limit := 10
	if len(stats) < limit {
		limit = len(stats)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("  %s: %d\n", stats[i].pkg, stats[i].count)
	}
}

// mergeTransitiveLinknames 合并传递性 linkname 链接
// 例如: a->b, b->c 合并为 a->c (当 b 不是真实函数时)
func mergeTransitiveLinknames(entries []types.LinknameEntry, verbose bool) []types.LinknameEntry {
	// 构建映射：decl -> impl
	declToImpl := make(map[string]string)
	for _, e := range entries {
		declToImpl[e.DeclFunc] = e.ImplFunc
	}

	// 存储原始 entry 的完整信息，用于更新时复制其他字段
	entryMap := make(map[string]types.LinknameEntry)
	for _, e := range entries {
		entryMap[e.DeclFunc] = e
	}

	var result []types.LinknameEntry
	mergedCount := 0

	for _, e := range entries {
		// 查找最终实现
		finalImpl, chain := findFinalImpl(e.ImplFunc, declToImpl)

		// 如果发生了传递（即最终实现不是直接实现）
		if finalImpl != e.ImplFunc && len(chain) > 1 {
			// 创建新的 entry
			newEntry := e
			newEntry.ImplFunc = finalImpl
			newEntry.ImplPkg = extractPackagePath(finalImpl)

			result = append(result, newEntry)
			mergedCount++

			if verbose {
				chainStr := strings.Join(chain, " -> ")
				fmt.Printf("合并传递链接: %s\n", chainStr)
			}
		} else {
			// 没有传递，保持原样
			result = append(result, e)
		}
	}

	if verbose && mergedCount > 0 {
		fmt.Printf("\n总共合并了 %d 条传递性链接\n", mergedCount)
	}

	return result
}

// findFinalImpl 沿着 linkname 链找到最终实现
// 返回最终实现的函数名和完整的链路
func findFinalImpl(implFunc string, declToImpl map[string]string) (string, []string) {
	visited := make(map[string]bool)
	chain := []string{implFunc}
	current := implFunc

	// 沿着链找，防止循环
	maxDepth := 100 // 防止无限循环
	depth := 0

	for depth < maxDepth {
		if visited[current] {
			// 检测到循环，返回当前位置
			if verbose := false; verbose {
				fmt.Printf("警告: 检测到循环引用 at %s\n", current)
			}
			return current, chain
		}
		visited[current] = true

		next, exists := declToImpl[current]
		if !exists {
			// 找到最终实现
			return current, chain
		}

		// 继续沿着链走
		current = next
		chain = append(chain, current)
		depth++
	}

	// 达到最大深度，返回当前位置
	fmt.Printf("警告: linkname 链过长 (>%d), 在 %s 处截断\n", maxDepth, current)
	return current, chain
}