package utils

import (
	"fmt"
	"regexp"
	"strings"
)

type SignatureMatcher struct {
	regex *regexp.Regexp
	raw   string
}

func NewSignatureMatcher(input string) (*SignatureMatcher, error) {
	// 定义一个能够匹配 Go 类型的 "ANY" 模式
	// 它的逻辑是：匹配 (普通字符) 或 (带中括号的内容) 或 (带小括号的内容)
	const strictAnyPattern = `(?:(?:[^,()\[\]]+|\[[^\]]*\]|\([^)]*\))+)`

	temps := strings.Split(input, "|")
	var regexParts []string

	for _, temp := range temps {
		temp = strings.TrimSpace(temp)
		if temp == "" {
			continue
		}

		// 1. 转义原始字符串，确保 . * [ ] 等被当做普通字符
		escaped := regexp.QuoteMeta(temp)

		// 2. 将转义后的 "ANY" 还原为占位符
		// QuoteMeta 会把 "ANY" 变成 "ANY"，这里用唯一标识符先占位
		const placeholder = "___ANY_PLACEHOLDER___"
		escaped = strings.ReplaceAll(escaped, "ANY", placeholder)

		// 3. 处理分隔符的空格容错
		// 将固定的 "," 变成能匹配 "空格,空格" 的正则
		escaped = strings.ReplaceAll(escaped, ",", `\s*,\s*`)
		// 将 "->" 变成能匹配 "空格->空格" 的正则
		escaped = strings.ReplaceAll(escaped, `\-\>`, `\s*->\s*`)
		// 允许左括号后、右括号前有空格
		escaped = strings.ReplaceAll(escaped, `\(`, `\(\s*`)
		escaped = strings.ReplaceAll(escaped, `\)`, `\s*\)`)
		escaped = strings.ReplaceAll(escaped, `\[`, `\[\s*`)
		escaped = strings.ReplaceAll(escaped, `\]`, `\s*\]`)

		// 4. 将占位符替换为我们设计的鲁棒正则
		// 使用非捕获组 (?:...) 避免产生多余的 Submatch
		finalRegexStr := strings.ReplaceAll(escaped, placeholder, strictAnyPattern)

		// 5. 加上首尾锚点，确保它是完整匹配整个签名
		regexParts = append(regexParts, "^"+finalRegexStr+"$")
	}

	if len(regexParts) == 0 {
		return nil, fmt.Errorf("empty signature template")
	}

	finalPattern := strings.Join(regexParts, "|")
	re, err := regexp.Compile(finalPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid signature regex: %w", err)
	}

	return &SignatureMatcher{
		regex: re,
		raw:   input,
	}, nil
}

func (sm *SignatureMatcher) Match(target string) bool {
	return sm.regex.MatchString(target)
}
