package utils

import (
	"encoding/json"
	"fmt"
	"os"
	. "linkname-analyzer/types"
)

func LoadLinknameMappings(jsonPath string) (
	map[string]ImplInfo, map[string]bool, error) {

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 JSON 文件失败: %w", err)
	}

	var entries []LinknameEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, nil, fmt.Errorf("JSON 解析失败: %w", err)
	}

	// 声明函数 → 实现函数映射
	lookup := make(map[string]ImplInfo)

	// 标记 ASM 实现的声明函数集合
	asmSet := make(map[string]bool)

	for _, e := range entries {
		lookup[e.DeclFunc] = ImplInfo{
			ImplFunc: e.ImplFunc,
			ImplPkg:  e.ImplPkg,
		}

		if e.IsAsm {
			asmSet[e.ImplFunc] = true
		}
	}

	return lookup, asmSet, nil
}