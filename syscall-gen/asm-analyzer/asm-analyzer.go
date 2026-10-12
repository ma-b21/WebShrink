package main

import (
	"bufio"
	"log/slog"
	"os"

	"encoding/json"
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"

	"asm-analyzer/types"
)

var funcSets []*types.AsmFunction

var callInstructions = types.NewSetFromSlice([]string{
	"CALL", "JA", "JAE", "JB", "JBE", "JC", "JE",
	"JEQ", "JG", "JGE", "JGT", "JHI", "JL", "JLE",
	"JLS", "JLT", "JMP", "JNC", "JNE", "JNZ", "JZ",
})

func main() {
	opts := &slog.HandlerOptions{AddSource: true}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	slog.SetDefault(logger) // 替换全局默认

	slog.Info("Go 版本: ", "version", runtime.Version())
	slog.Info("开始分析 Go 标准库...")

	// 加载所有标准库包
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
	}

	slog.Info("工作路径：", "path", cfg.Dir)
	slog.Info("正在加载标准库包...")
	pkgs, err := packages.Load(cfg, "std", "vendor/golang.org/x/...")
	if err != nil {
		slog.Error("加载标准库失败")
	}
	for _, pkg := range pkgs {
		// pkg.GoFiles - Go 源文件
		// pkg.CgoFiles - Cgo 文件
		// pkg.OtherFiles - 其他文件（包括 .s 汇编）
		for _, asmFile := range pkg.OtherFiles {
			if strings.HasSuffix(asmFile, ".s") {
				slog.Info("分析汇编文件:", "file", asmFile, "package", pkg.PkgPath)
				analyzeAsmFile(asmFile, pkg.PkgPath)
			}
		}
	}

	handleSpecialFuncs()
	if err := ExportFuncSets("func_sets.json"); err != nil {
		slog.Error("导出函数集合到文件失败")
	}
}

// ExportFuncSets 导出 funcSets 为 JSON 文件
func ExportFuncSets(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	return encoder.Encode(funcSets)
}

func handleSpecialFuncs() {
	for _, asmFunc := range funcSets {
		switch asmFunc.FuncName {
		case "runtime.switchToCrashStack0":
			asmFunc.Callees = append(asmFunc.Callees, "builtins.print",
				                                      "runtime.traceback1",
				                                      "runtime.throw")
		case "runtime.clone":
			asmFunc.Callees = append(asmFunc.Callees, "runtime.mstart", "runtime._rt0_amd64_lib_go")
		case "runtime.systemstack":
			asmFunc.Callees = append(asmFunc.Callees, "runtime.badsystemstack")
		case "runtime.reflectcall":
			asmFunc.Callees = append(asmFunc.Callees, "runtime.badreflectcall")
		case "runtime.nanotime1":
			asmFunc.Syscalls = append(asmFunc.Syscalls, "228") // SYS_clock_gettime
		case "runtime.vgetrandom1":
			asmFunc.Syscalls = append(asmFunc.Syscalls, "318") // SYS_getrandom
		case "time.now":
			asmFunc.Syscalls = append(asmFunc.Syscalls, "228") // SYS_clock_gettime
		case "syscall.gettimeofday":
			asmFunc.Syscalls = append(asmFunc.Syscalls, "96")  // SYS_gettimeofday
		default:
			continue
		}
		asmFunc.Callees = uniqueStrings(asmFunc.Callees)
		asmFunc.Syscalls = uniqueStrings(asmFunc.Syscalls)
	}
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

func qualifiedName(pkg, funcName string) string {
	if strings.HasPrefix(funcName, "Register") {
		return funcName
	}

	if strings.HasPrefix(funcName, "·") {
		funcName = pkg + funcName
	} else if !strings.Contains(funcName, "·") {
		funcName = pkg + "·" + funcName
	}
	funcName = strings.ReplaceAll(funcName, "∕", "/")
	funcName = strings.ReplaceAll(funcName, "·", ".")
	if strings.Contains(funcName, "<ABIInternal>") {
		funcName = strings.Split(funcName, "<")[0]
	}

	return funcName
}

func HasUpper(s string) bool {
	for _, r := range s { // 遍历字符串的每个 Unicode 字符
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.IsUpper(r) { // 判断是否为大写字母
			return true
		}
	}
	return false
}

func HasLower(s string) bool {
	for _, r := range s { // 遍历字符串的每个 Unicode 字符
		if !unicode.IsLetter(r) {
			continue
		}
		if unicode.IsLower(r) { // 判断是否为大写字母
			return true
		}
	}
	return false
}

func judgeCallee(callee string) string {
	if callee[len(callee)-1] == ';' {
		callee = callee[:len(callee)-1]
	}
	if !HasUpper(callee) {
		return ""
	}
	if strings.HasSuffix(callee, "(SB)") {
		return strings.Split(callee, "(SB)")[0]
	}
	return ""
}

var syscallMap = map[string]string{
	"SYS_read": "0",
	"SYS_write": "1",
	"SYS_close": "3",
	"SYS_mmap": "9",
	"SYS_munmap": "11",
	"SYS_brk": "12",
	"SYS_rt_sigaction": "13",
	"SYS_rt_sigprocmask": "14",
	"SYS_rt_sigreturn": "15",
	"SYS_sched_yield": "24",
	"SYS_mincore": "27",
	"SYS_madvise": "28",
	"SYS_nanosleep": "35",
	"SYS_setittimer": "38",
	"SYS_getpid": "39",
	"SYS_socket": "41",
	"SYS_connect": "42",
	"SYS_clone": "56",
	"SYS_exit": "60",
	"SYS_kill": "62",
	"SYS_ftruncate": "77",
	"SYS_prctl": "157",
	"SYS_gettimeofday": "96",
	"SYS_sigaltstack": "131",
	"SYS_arch_prctl": "158",
	"SYS_gettid": "186",
	"SYS_futex": "202",
	"SYS_sched_getaffinity": "204",
	"SYS_timer_create": "222",
	"SYS_timer_settime": "223",
	"SYS_timer_delete": "226",
	"SYS_clock_gettime": "228",
	"SYS_exit_group": "231",
	"SYS_tgkill": "234",
	"SYS_openat": "257",
	"SYS_faccessat": "269",
	"SYS_pipe2": "293",
}

func analyzeAsmFile(fileName, pkg string) {
	file, err := os.Open(fileName)
	if err != nil {
		slog.Error("汇编文件打开失败", "file", fileName)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	preline := ""
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过无效行
		if shouldSkipLine(line) {
			continue
		}

		if strings.HasPrefix(line, "TEXT") {
			// 函数符号提取
			funcName := strings.Split(line[5:], "(SB)")[0]
			funcName = qualifiedName(pkg, funcName)
			funcSets = append(funcSets, &types.AsmFunction{FuncName: funcName})
			continue
		}

		// 对callee和funcname提取完全限定名函数
		call := strings.Fields(line)[0]
		if callInstructions.Has(call) {
			callee := strings.Fields(line)[1]
			callee = judgeCallee(callee)
			if callee == "" {
				continue
			}
			callee = qualifiedName(pkg, callee)
			funcSets[len(funcSets)-1].Callees = append(funcSets[len(funcSets)-1].Callees, callee)
		}
		if call == "SYSCALL" {
			if !strings.HasPrefix(preline, "MOV") {
				slog.Error("No Syscall MOV Instruction", "line", line, "preline", preline)
			}
			funcSets[len(funcSets)-1].SyscallLine = append(funcSets[len(funcSets)-1].SyscallLine, lineNum)
			syscallName := strings.Split(strings.Fields(preline)[1], ",")[0]
			if !strings.HasPrefix(syscallName, "$") {
				slog.Error("Syscall Parameters are Variable", "func", funcSets[len(funcSets)-1].FuncName)
				// syscallName = "Variable " + syscallName
				continue
			} else {
				if name, ok := syscallMap[syscallName[1:]]; ok {
					syscallName = name
				} else {
					slog.Error("Syscall Not in Map", "syscall", syscallName)
				}
			}
			funcSets[len(funcSets)-1].Syscalls = append(funcSets[len(funcSets)-1].Syscalls, syscallName)
		}
		preline = line
	}

	if err := scanner.Err(); err != nil {
		slog.Error("读取文件出错", "error", err)
	}
}

func shouldSkipLine(line string) bool {
	return len(line) == 0 ||
		strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "*/")
}
