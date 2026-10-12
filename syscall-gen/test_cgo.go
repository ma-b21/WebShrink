// test_cgo.go checks DNS and user lookup with and without CGO.
package main

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
)

func main() {
	fmt.Println("=== Quick CGO Behavior Test ===")
	fmt.Printf("Go: %s, OS: %s, Arch: %s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("GODEBUG: %s\n\n", os.Getenv("GODEBUG"))
	
	// 测试DNS
	fmt.Println("--- DNS Test ---")
	testDNS()
	
	// 测试用户查询
	fmt.Println("\n--- User Lookup Test ---")
	testUser()
	
	// 打印关键配置
	fmt.Println("\n--- Config Files ---")
	printConfig()
}

func testDNS() {
	domains := []string{"google.com", "localhost"}
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			fmt.Printf("  %s: ERROR - %v\n", domain, err)
		} else {
			fmt.Printf("  %s: %v\n", domain, ips)
		}
	}
}

func testUser() {
	// 当前用户
	if u, err := user.Current(); err != nil {
		fmt.Printf("  Current: ERROR - %v\n", err)
	} else {
		fmt.Printf("  Current: %s (UID: %s)\n", u.Username, u.Uid)
	}
	
	// 查找root
	if u, err := user.Lookup("root"); err != nil {
		fmt.Printf("  root: ERROR - %v\n", err)
	} else {
		fmt.Printf("  root: UID=%s, Home=%s\n", u.Uid, u.HomeDir)
	}
	
	// 通过UID查找
	if u, err := user.LookupId("0"); err != nil {
		fmt.Printf("  UID 0: ERROR - %v\n", err)
	} else {
		fmt.Printf("  UID 0: %s\n", u.Username)
	}
}

func printConfig() {
	// nsswitch.conf
	if data, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		fmt.Println("  /etc/nsswitch.conf (hosts):")
		for _, line := range splitLines(string(data)) {
			if len(line) >= 5 && line[:5] == "hosts" {
				fmt.Printf("    %s\n", line)
			}
		}
	}
	
	// resolv.conf
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		fmt.Println("  /etc/resolv.conf:")
		lines := splitLines(string(data))
		for i, line := range lines {
			if i < 3 { // 只显示前3行
				fmt.Printf("    %s\n", line)
			}
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				lines = append(lines, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

/*
编译和运行：

# 测试CGO=0（纯Go）
CGO_ENABLED=0 go build -o test_nocgo test_cgo.go
./test_nocgo

# 测试CGO=1
CGO_ENABLED=1 go build -o test_cgo test_cgo.go
./test_cgo

# 测试osusergo标签（纯Go用户查询）
CGO_ENABLED=0 go build -tags osusergo -o test_osusergo test_cgo.go
./test_osusergo

# 使用strace查看系统调用差异
strace -e trace=socket,connect,sendto,recvfrom,open,openat ./test_nocgo 2>&1 | grep -E "socket|connect|sendto|open"
strace -e trace=socket,connect,sendto,recvfrom,open,openat ./test_cgo 2>&1 | grep -E "socket|connect|sendto|open"

# 强制使用特定DNS解析器
GODEBUG=netdns=go ./test_cgo      # 强制纯Go解析器
GODEBUG=netdns=cgo ./test_cgo     # 强制CGO解析器（需要CGO编译）

# 查看二进制依赖
ldd test_nocgo  # 应该显示 "not a dynamic executable" 或只有极少依赖
ldd test_cgo    # 会显示libc等依赖
*/
