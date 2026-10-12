package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type sysdigProcessEntry struct {
	Pid     *int   `json:"proc.pid"`
	PPid    *int   `json:"proc.ppid"`
	Tid     *int   `json:"thread.tid"`
	Type    string `json:"evt.type"`
	Info    string `json:"evt.info"`
	Name    string `json:"proc.name"`
	ExePath string `json:"proc.exepath"`
	Cmdline string `json:"proc.cmdline"`
}

type SysdigProcessEvent struct {
	Pid     int
	PPid    int
	Tid     int
	Type    string
	Info    string
	Name    string
	ExePath string
	Cmdline string
}

func parseInfoNumericField(info string, prefixes ...string) int {
	for _, prefix := range prefixes {
		idx := strings.Index(info, prefix)
		if idx == -1 {
			continue
		}
		start := idx + len(prefix)
		end := start
		for end < len(info) {
			ch := info[end]
			if ch < '0' || ch > '9' {
				break
			}
			end++
		}
		if end == start {
			continue
		}
		value, err := strconv.Atoi(info[start:end])
		if err == nil && value != 0 {
			return value
		}
	}
	return 0
}

func decodeSysdigPID(entry sysdigProcessEntry) int {
	if entry.Pid != nil && *entry.Pid != 0 {
		return *entry.Pid
	}
	if entry.Tid != nil && *entry.Tid != 0 {
		return *entry.Tid
	}
	if value := parseInfoNumericField(entry.Info, " pid=", "pid="); value != 0 {
		return value
	}
	return parseInfoNumericField(entry.Info, " tid=", "tid=")
}

func decodeSysdigPPID(entry sysdigProcessEntry) int {
	if entry.PPid != nil && *entry.PPid != 0 {
		return *entry.PPid
	}
	return parseInfoNumericField(entry.Info, " ptid=", "ptid=", " ppid=", "ppid=")
}

func DecodeSysdigProcessEvent(rawBytes []byte) (SysdigProcessEvent, error) {
	var entry sysdigProcessEntry
	if err := json.Unmarshal(rawBytes, &entry); err != nil {
		return SysdigProcessEvent{}, err
	}

	event := SysdigProcessEvent{
		Pid:     decodeSysdigPID(entry),
		PPid:    decodeSysdigPPID(entry),
		Type:    entry.Type,
		Info:    entry.Info,
		Name:    entry.Name,
		ExePath: entry.ExePath,
		Cmdline: entry.Cmdline,
	}
	if entry.Tid != nil {
		event.Tid = *entry.Tid
	}
	return event, nil
}


// LoadSysdigSyscallsFromFile 读取 JSONL 文件并返回 PID -> 系统调用列表 的映射。
// 这里只保留“该 PID 自己实际出现过的 syscall type 集”。
// 进程树级的祖先归并由 builder/subprocess.go 中的 GetSubProcessSyscall 统一负责，
// 避免在这里先递归吞并子孙事件，再在上层按 traced ancestor 二次归并。
func LoadSysdigSyscallsFromFile(filePath string) (map[string][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	pidEvents := make(map[string]map[string]struct{})

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 10*1024*1024) 
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		rawBytes := scanner.Bytes()
		if len(rawBytes) == 0 {
			continue
		}

		event, err := DecodeSysdigProcessEvent(rawBytes)
		if err != nil {
			continue
		}
		if event.Type == "" || event.Pid == 0 {
			continue
		}

		pidStr := strconv.Itoa(event.Pid)

		if pidEvents[pidStr] == nil {
			pidEvents[pidStr] = make(map[string]struct{})
		}
		pidEvents[pidStr][event.Type] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	finalResult := make(map[string][]string, len(pidEvents))
	for pid, syscallSet := range pidEvents {
		list := make([]string, 0, len(syscallSet))
		for sc := range syscallSet {
			list = append(list, sc)
		}
		finalResult[pid] = list
	}

	// --- Debug 输出 ---
	fileOut, err := os.Create("./tmp/sysdig_syscalls_output.json")
	if err == nil {
		defer fileOut.Close()
		encoder := json.NewEncoder(fileOut)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(finalResult)
	}

	return finalResult, nil
}
