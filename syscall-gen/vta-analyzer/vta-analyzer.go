package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"

	"vta-analyzer/builder"
)

func main() {
	var (
		inputFile    string
		mainPkg      string
		linknameJson string
		builtinFile  string
		asmGraphFile string
		stringOutput bool

		// 若有额外接口调用或反射调用，则指定该文件
		extraEdgeFile string

		// 子进程分析相关参数
		traceLogFile     string
		sysdigLogFile    string
		handlerFuncSig   string
		graphSyscallFile string

		mode       string
		buildFlags string
		memProfile string
	)
	flag.StringVar(&inputFile, "file", "", "输入的Go代码文件路径")
	flag.StringVar(&mainPkg, "main-pkg", "", "主程序包路径，用于将 runtime 名称中的 main 归一化为真实包名")
	flag.StringVar(&linknameJson, "linkname", "linkname_mappings.json", "linkname映射的JSON文件路径")
	flag.StringVar(&builtinFile, "builtins", "functions.go", "内置函数的go假声明文件路径")
	flag.StringVar(&asmGraphFile, "asm", "func_sets.json", "汇编调用图JSON文件路径")
	flag.StringVar(&extraEdgeFile, "extra-edge", "", "对于反射和接口调用的补充调用边")
	flag.BoolVar(&stringOutput, "syscall-name", false, "默认以syscall num输出, 开启后以syscall name输出")
	flag.StringVar(&traceLogFile, "trace-log", "", "子进程调用栈日志文件路径")
	flag.StringVar(&sysdigLogFile, "sysdig-log", "./log.jsonl", "子进程系统调用日志文件路径")
	flag.StringVar(&handlerFuncSig, "handler-func", "", "子进程处理函数签名, 形如 \"(param type, param type) -> [return type, return type]\"")
	flag.StringVar(&graphSyscallFile, "graph-syscall", "./tmp/dag_syscalls.json", "调用图文件路径")
	flag.StringVar(&mode, "mode", "default", "分析模式: default / subprocess")
	flag.StringVar(&buildFlags, "build-flags", "", "构建标志")
	flag.StringVar(&memProfile, "memprofile", "", "将 heap profile 写入指定文件，供 go tool pprof 分析")
	flag.Parse()

	if memProfile != "" {
		writeProfile := installMemProfileSignalHandler(memProfile)
		defer func() {
			writeProfile()
		}()
	}

	fmt.Printf("Go 版本: %s\n", runtime.Version())
	fmt.Println("开始分析 Go 标准库...")
	os.MkdirAll("./tmp", 0755)

	if buildFlags != "" {
		builder.BuildFlags = strings.Split(buildFlags, " ")
		fmt.Printf("使用构建标志: %v\n", builder.BuildFlags)
	}

	if mode == "subprocess" {
		if traceLogFile == "" || handlerFuncSig == "" {
			log.Fatal("子进程模式需要 -trace-log 和 -handler-func 参数")
		}
		fmt.Println("子进程模式: 仅分析子进程系统调用...")
		subProcSyscalls := builder.GetSubProcessSyscall(mainPkg, traceLogFile, sysdigLogFile, handlerFuncSig, graphSyscallFile)
		if subProcSyscalls == nil {
			log.Fatal("未找到子进程系统调用")
		}
		dag := &builder.DAG{
			Nodes: make(map[string]*builder.DAGNode),
		}
		err := dag.ImportJSON(graphSyscallFile)
		if err != nil {
			log.Fatalf("加载调用图失败: %v", err)
		}
		fmt.Println("重建 SCC 图...")
		dag.ComputeSCC()
		dag.BuildSCCGraph()
		fmt.Println("添加子进程系统调用...")
		for funcName, syscallNums := range subProcSyscalls {
			dag.AddSyscallsToNode(funcName, syscallNums)
		}
		fmt.Println("重新传播系统调用...")
		dag.PropagateSyscalls()
		fmt.Println("导出更新后的调用图...")
		err = dag.ExportJSON("./tmp/dag_syscalls_subproc.json", stringOutput)
		if err != nil {
			log.Fatalf("保存 DAG JSON 失败: %v", err)
		}
		fmt.Println("更新后的 DAG 系统调用结果已保存到: ./tmp/dag_syscalls_subproc.json")
		return
	}

	if mode != "default" {
		log.Fatalf("未知的分析模式: %s", mode)
	}

	if inputFile == "" {
		log.Fatal("请使用 -file 参数指定输入的Go代码文件或包路径")
	}

	builder.SetBuiltinDeclFile(transPathToPkgPath(builtinFile))

	loadPath := transPathToPkgPath(inputFile)
	declImplMap, err := builder.LoadDeclImplMap(linknameJson)
	if err != nil {
		log.Fatalf("加载 linkname 映射失败: %v", err)
	}

	extraEdges := builder.GetExtraEdges(extraEdgeFile)

	unifiedGraph := builder.GetVtaGraphsForModule(loadPath, mainPkg, declImplMap, extraEdges)


	fmt.Printf("加载汇编调用图: %s\n", asmGraphFile)
	asmFuncs, err := builder.LoadAsmCallGraphFromFile(asmGraphFile)
	if err != nil {
		log.Fatalf("加载汇编调用图失败: %v", err)
	}

	fmt.Printf("合并 VTA 调用图和汇编调用图...\n")
	unifiedGraph = builder.MergeCallGraphs(unifiedGraph, nil, asmFuncs, declImplMap)
	if err := builder.EnrichImportedGraphMetadata(loadPath, unifiedGraph); err != nil {
		log.Fatalf("补全 VTA 边元数据失败: %v", err)
	}
	// 增加寄存器调用
	fmt.Println("加载 mcall 与 systemstack 调用...")
	builder.AddRegisterCall(unifiedGraph, declImplMap)
	fmt.Println("分析 Syscall 参数流...")
	builder.AddSyscallNum(unifiedGraph)

	if extraEdgeFile != "" {
		fmt.Println("增加额外接口调用与反射调用...")
		builder.AddExtraEdge(unifiedGraph, extraEdges, mainPkg)
	}

	fmt.Printf("最终统一调用图包含 %d 个节点，%d 条边\n",
		unifiedGraph.GetNodeCount(), unifiedGraph.GetEdgeCount())
	// 保存为DOT格式
	outputDot := "./tmp/callgraph.dot"
	err = saveUnifiedGraphToDot(unifiedGraph, outputDot)
	if err != nil {
		log.Fatalf("保存DOT文件失败: %v", err)
	}
	fmt.Printf("调用图已保存到: %s\n", outputDot)

	// 构建 DAG 并计算强连通分量
	fmt.Println("构建 DAG 并计算强连通分量...")
	dag := builder.BuildDAG(unifiedGraph)

	fmt.Println("计算强连通分量...")
	dag.ComputeSCC()

	fmt.Println("构建 SCC 图...")
	dag.BuildSCCGraph()

	fmt.Println("传播系统调用...")
	dag.PropagateSyscalls()

	// 输出统计信息
	nodeCount, edgeCount, sccCount, maxSCCSize := dag.GetStats()
	fmt.Printf("DAG 统计:\n")
	fmt.Printf("  节点数: %d\n", nodeCount)
	fmt.Printf("  边数: %d (排除接口调用和 dynamic-func)\n", edgeCount)
	fmt.Printf("  强连通分量数: %d\n", sccCount)
	fmt.Printf("  最大 SCC 大小: %d\n", maxSCCSize)

	// 导出 DAG 结果
	fmt.Println("导出 DAG 结果...")
	err = dag.ExportJSON("./tmp/dag_syscalls.json", stringOutput)
	if err != nil {
		log.Fatalf("保存 DAG JSON 失败: %v", err)
	}
	fmt.Println("DAG 系统调用结果已保存到: ./tmp/dag_syscalls.json")


	// 导出所有 SCC 统计信息
	fmt.Println("导出 SCC 统计信息...")
	err = dag.ExportAllSCCsInfo("./tmp/scc_stats.txt")
	if err != nil {
		log.Printf("导出 SCC 统计信息失败: %v", err)
	} else {
		fmt.Println("SCC 统计信息已保存到: ./tmp/scc_stats.txt")
	}


	unifiedGraph.ExportAsSimpleTreeJSON("./tmp/callgraph.json")
}

func transPathToPkgPath(filePath string) string {
	if strings.HasSuffix(filePath, ".go") {
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			log.Fatalf("无法获取绝对路径: %v", err)
		}
		filePath = absPath
	}

	if strings.HasSuffix(filePath, ".go") {
		filePath = "file=" + filePath
	}
	return filePath
}

func saveUnifiedGraphToDot(ucg *builder.UnifiedCallGraph, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "digraph unified_callgraph {")
	fmt.Fprintln(file, "  node [shape=box];")
	fmt.Fprintln(file, "  rankdir=TB;")

	nodeIDs := make(map[string]int)
	nodeID := 0

	// 遍历所有节点
	for key, node := range ucg.Nodes {
		nodeIDs[key] = nodeID

		label := key
		style := ""

		// 根据节点类型设置样式
		if node.IsAsm && !node.HasSSA {
			// 纯汇编节点
			style = " style=filled fillcolor=lightcoral"
			label = fmt.Sprintf("%s\\n[ASM]", key)
		} else if node.HasSSA && node.Asm != nil {
			// 混合节点（既有 Go 又有汇编）
			style = " style=filled fillcolor=lightyellow"
			label = fmt.Sprintf("%s\\n[GO+ASM]", key)
		} else {
			// 纯 Go 节点
			if ucg.Root != nil && node.Key == ucg.Root.Key {
				style = " style=filled fillcolor=lightblue"
			}
		}

		// 添加系统调用信息
		if len(node.Syscalls) > 0 {
			label = fmt.Sprintf("%s\\nSyscalls: %d", label, len(node.Syscalls))
		}

		fmt.Fprintf(file, "  n%d [label=\"%s\"%s];\n", nodeID, escapeLabel(label), style)
		nodeID++
	}

	// 遍历所有边
	for key, node := range ucg.Nodes {
		callerID := nodeIDs[key]
		for _, edge := range node.Out {
			if edge.Callee != nil {
				calleeID := nodeIDs[edge.Callee.Key]

				edgeLabel := ""
				edgeStyle := ""

				// 根据边的来源设置样式
				switch edge.Source {
				case "vta":
					edgeStyle = " [color=blue]"
					if edge.VTA != nil && edge.VTA.HasSite {
						edgeLabel = " [label=\"VTA\" color=blue fontsize=8]"
					}
				case "asm":
					edgeStyle = " [color=red style=dashed]"
					edgeLabel = " [label=\"ASM\" color=red fontsize=8 style=dashed]"
				case "builtin":
					edgeStyle = " [color=green]"
					edgeLabel = " [label=\"builtin\" color=green fontsize=8]"
				}

				if edgeLabel != "" {
					fmt.Fprintf(file, "  n%d -> n%d%s;\n", callerID, calleeID, edgeLabel)
				} else {
					fmt.Fprintf(file, "  n%d -> n%d%s;\n", callerID, calleeID, edgeStyle)
				}
			}
		}
	}

	fmt.Fprintln(file, "}")
	return nil
}

func writeHeapProfile(path string) error {
	runtime.GC()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pprof.WriteHeapProfile(file)
}

func installMemProfileSignalHandler(path string) func() {
	var once sync.Once

	writeProfile := func() {
		once.Do(func() {
			if err := writeHeapProfile(path); err != nil {
				log.Printf("写入 heap profile 失败: %v", err)
				return
			}
			fmt.Printf("Heap profile 已保存到: %s\n", path)
		})
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("收到信号 %s，正在写入 heap profile...", sig)
		writeProfile()
		exitCode := 130
		if s, ok := sig.(syscall.Signal); ok {
			exitCode = 128 + int(s)
		}
		os.Exit(exitCode)
	}()

	return writeProfile
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
