package utils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

func LoadSyscallMap() (map[int]string, error) {
	cmd := exec.Command("ausyscall", "--dump")
	out, err := cmd.Output()
	if err != nil {
		// 判断是否是 command not found
		var ee *exec.Error
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("ausyscall 未安装，请执行: sudo apt install auditd")
		}
		return nil, fmt.Errorf("执行 'ausyscall --dump' 失败: %v", err)
	}

	syscallMap := make(map[int]string)
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 格式: "0       read"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		num, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		name := fields[1]
		syscallMap[num] = name
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("解析输出失败: %v", err)
	}

	return syscallMap, nil
}

// ParseRuntimeName 解析 Runtime 函数名，返回 (包名, SSA格式函数名)
func ParseRuntimeName(runtimeName string) (pkgName string, ssaName string) {
	name := runtimeName

	var genericPart string = ""
	// 查找最外层的方括号
	startBracket := strings.Index(name, "[")
	endBracket := strings.LastIndex(name, "]")
	funcIdxTemp := strings.Index(name, ".func")

	// 提取条件：存在 [] 且它们不在 .func 后缀里面（即属于函数签名的一部分）
	if startBracket != -1 && endBracket != -1 && endBracket > startBracket && (funcIdxTemp == -1 || startBracket < funcIdxTemp) {
		genericPart = name[startBracket : endBracket+1]
		// 暂时移除泛型部分，方便后续逻辑处理
		name = name[:startBracket] + name[endBracket+1:]
	}

	var partA, partB string
	funcIdx := strings.Index(name, ".gowrap")
	if funcIdx != -1 {
		name = name[:funcIdx]
	}
	funcIdx = strings.Index(name, ".deferwrap")
	if funcIdx != -1 {
		name = name[:funcIdx]
	}

	funcIdx = strings.Index(name, ".func")

	if funcIdx == -1 {
		partA = name
		partB = ""
	} else {
		partA = name[:funcIdx]
		partB = name[funcIdx:] // 例如: .func3.1
	}

	// Rule 2: 提取包名 (从 A 部分提取)
	lastSlash := strings.LastIndex(partA, "/")
	searchStart := 0
	if lastSlash != -1 {
		searchStart = lastSlash + 1
	}

	// 找 partA 中最后一个斜杠之后，第一个点之前的内容作为包名
	dotAfterSlash := strings.Index(partA[searchStart:], ".")

	// 检测 gopkg.in/yaml.v2 这种情况：
	// 只有 gopkg.in 的导入路径会把版本号编码成 ".v2" 这样的包路径后缀。
	// 其他形如 "prometheus.v2.NewDesc" 的名字通常是包内类型/接收者名为 v2，
	// 不能把 ".v2" 误判成包版本，否则会把方法解析成不存在的包路径。
	if dotAfterSlash != -1 && strings.HasPrefix(partA, "gopkg.in/") {
		// 计算点在 partA 中的绝对位置
		absDotIdx := searchStart + dotAfterSlash

		// 检查边界并匹配 pattern: .v[0-9]
		if absDotIdx+2 < len(partA) && partA[absDotIdx+1] == 'v' && partA[absDotIdx+2] >= '0' && partA[absDotIdx+2] <= '9' {
			// 从当前版本号之后继续寻找下一个点
			// searchStr 是 ".v2.funcName" 这样的结构
			searchStr := partA[absDotIdx+1:]
			secondDot := strings.Index(searchStr, ".")

			if secondDot != -1 {
				// 如果找到了第二个点，说明那才是真正的包名结束位置
				// 更新 dotAfterSlash：原位置 + 1(跳过第1个点) + 第二个点的相对位置
				dotAfterSlash += 1 + secondDot
			}
		}
	}

	if dotAfterSlash == -1 {
		pkgName = partA
	} else {
		splitIdx := searchStart + dotAfterSlash
		pkgName = partA[:splitIdx]
	}

	// Rule 3: 处理显式 init 函数 (.init.0 -> .init#1)
	// 逻辑：如果在 .func 之前的部分(partA) 是以 .init.数字 结尾
	// init 函数没有接收者，所以处理完这个后可以直接拼接 partB 返回，跳过 processPartA
	if initIdx := strings.LastIndex(partA, ".init."); initIdx != -1 {
		// 获取 .init. 后面的部分，期望是数字
		numberPart := partA[initIdx+len(".init."):]
		if num, err := strconv.Atoi(numberPart); err == nil {
			// 如果转换成功，说明确实是 .init.0, .init.1 这种格式

			// 1. 构造前半部分: .../pkg.init
			// 注意：这里保留 .init，因为 SSA 格式是 .init#NUM
			baseName := partA[:initIdx+len(".init")]

			// 2. 构造 SSA 名字: .../pkg.init#1 (数字+1)
			newPartA := baseName + "#" + strconv.Itoa(num+1)

			// 3. 处理 PartB (匿名函数部分，例如 init 里启动了 goroutine: .init.0.func1)
			// 注意这里假设 ProcessPartB 已经处理了 .funcN -> $N 的逻辑
			processedB := processPartB(partB)

			// 4. 直接返回，跳过 processPartA (因为 init 没有接收者)
			return unescape(pkgName), unescape(newPartA + processedB)
		}
	}

	// Rule 4 & 5: 处理 A (接收者转换)
	processedA := processPartA(partA, pkgName)

	// Rule 6: 处理 B (闭包后缀转换)
	processedB := processPartB(partB)

	if genericPart != "" {
		// 情况 1: 有接收者 (Method) -> 插入到 ). 之前
		if idx := strings.LastIndex(processedA, ")."); idx != -1 {
			processedA = processedA[:idx] + genericPart + processedA[idx:]
		}
		// 情况 2: 普通泛型函数 (Non-method) -> 不需要插入到接收者里，因为没有接收者

		// 公共操作: 无论是不是方法，都要在函数名末尾加上实例化参数 [T]
		processedA = processedA + genericPart
	}

	// Rule 7: 拼接
	return unescape(pkgName), unescape(processedA + processedB)
}

// ParseRuntimeNameWithMainPkg resolves runtime names in the same way as
// ParseRuntimeName and additionally rewrites package "main" to the provided
// main package import path.
func ParseRuntimeNameWithMainPkg(runtimeName string, mainPkg string) (pkgName string, ssaName string) {
	runtimeName = rewriteRuntimeMainPrefix(runtimeName, mainPkg)

	pkgName, ssaName = ParseRuntimeName(runtimeName)
	if pkgName != "main" || mainPkg == "" {
		return pkgName, ssaName
	}

	return mainPkg, strings.Replace(ssaName, "main", mainPkg, 1)
}

func rewriteRuntimeMainPrefix(runtimeName string, mainPkg string) string {
	if mainPkg == "" || !strings.HasPrefix(runtimeName, "main.") {
		return runtimeName
	}

	tail := strings.TrimPrefix(runtimeName, "main.")
	if head, rest, ok := strings.Cut(tail, "."); ok && head == "main" {
		tail = rest
	}

	return mainPkg + "." + tail
}

// processPartA 处理主函数逻辑 (指针/值接收者)
func processPartA(a string, pkgName string) string {
	// 指针接收者: pkg.(*Type).Method -> (*pkg.Type).Method
	// 指针接收者的特征独立且唯一，先处理不会受版本号干扰
	if strings.Contains(a, "(*") {
		s := strings.Replace(a, "(*", "", 1)
		return "(*" + s
	}

	// 值接收者: pkg.Type.Method -> (pkg.Type).Method
	// 判断标准：去掉正确的包名后，提取剩余部分(例如: ".Type.Method" 或是 ".FuncName")
	// 如果剩余部分点的数量大于 1，说明中间存在结构体 Type，属于值接收者
	remainder := a
	if strings.HasPrefix(a, pkgName) {
		remainder = a[len(pkgName):]
	}

	// 比如 remainder 是 ".Type.Method" (点数 >= 2) -> 值接收者
	// 比如 remainder 是 ".FuncName" (点数 == 1) -> 普通函数
	if strings.Count(remainder, ".") > 1 {
		lastDot := strings.LastIndex(a, ".")
		return "(" + a[:lastDot] + ")" + a[lastDot:]
	}

	return a
}

// processPartB 处理闭包 (.func3.1 -> $3$1)
func processPartB(b string) string {
	if b == "" {
		return ""
	}

	// 假设 b 是 ".func3.1"

	// 1. 将 ".func" 替换为 "$"
	// 结果: "$3.1"
	s := strings.Replace(b, ".func", "$", 1)

	// 2. 将剩余的所有 "." 替换为 "$" (处理多层嵌套)
	// 结果: "$3$1"
	s = strings.ReplaceAll(s, ".", "$")

	return s
}

func unescape(s string) string {
	res, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return res
}
