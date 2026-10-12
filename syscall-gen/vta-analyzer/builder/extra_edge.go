package builder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vta-analyzer/utils"
)

type ExtraCallTarget struct {
	RuntimeName  string
	CallsiteLine int
	CallsiteCol  int
}

type CallInfo struct {
	File   string
	Line   int
	Col    int
	Callee []ExtraCallTarget
}

type rawCallInfo struct {
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Col    int      `json:"col"`
	Callee []string `json:"callee"`
}

type runtimeNameCandidate struct {
	PkgPath string
	SSAName string
}

var extraCalleeCache = make(map[string]string)

var suppressedExtraEdgeCallers = map[string]bool{
	"(*sync.Once).doSlow": true,
}

func (c CallInfo) CallerPathWithLine() string {
	if c.File == "" {
		return c.File
	}
	if c.Line > 0 {
		return fmt.Sprintf("%s:%d", c.File, c.Line)
	}
	if len(c.Callee) == 0 || c.Callee[0].CallsiteLine <= 0 {
		return c.File
	}

	return fmt.Sprintf("%s:%d", c.File, c.Callee[0].CallsiteLine)
}

func (t ExtraCallTarget) cacheKey(caller string) string {
	return fmt.Sprintf("%s|%s|%d|%d", caller, t.RuntimeName, t.CallsiteLine, t.CallsiteCol)
}

func GetExtraEdges(filePath string) map[string]CallInfo {
	if filePath == "" {
		return nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		panic("Extra Edge File Read Error")
	}

	raw := make(map[string]rawCallInfo)
	if err := json.Unmarshal(data, &raw); err != nil {
		panic("Extra Edge File Load Error")
	}

	parsed := make(map[string]CallInfo, len(raw))
	for caller, callInfo := range raw {
		info := CallInfo{
			File:   callInfo.File,
			Line:   callInfo.Line,
			Col:    callInfo.Col,
			Callee: make([]ExtraCallTarget, 0, len(callInfo.Callee)),
		}
		for _, callee := range callInfo.Callee {
			info.Callee = append(info.Callee, parseExtraCallTarget(callee))
		}
		parsed[caller] = info
	}

	return parsed
}

func parseExtraCallTarget(raw string) ExtraCallTarget {
	target := ExtraCallTarget{RuntimeName: raw}

	parts := strings.Split(raw, ":")
	if len(parts) < 3 {
		return target
	}

	line, errLine := strconv.Atoi(parts[len(parts)-2])
	col, errCol := strconv.Atoi(parts[len(parts)-1])
	if errLine != nil || errCol != nil {
		return target
	}

	target.RuntimeName = strings.Join(parts[:len(parts)-2], ":")
	target.CallsiteLine = line
	target.CallsiteCol = col
	return target
}

func callerSourceCandidates(callInfo CallInfo, unified *UnifiedCallGraph) []*UnifiedNode {
	if unified == nil || callInfo.File == "" || callInfo.Line <= 0 {
		return nil
	}

	lookup := unified.getNodeLookup()
	if lookup == nil {
		return nil
	}

	file := filepath.Clean(normalizeTraceSourcePath(callInfo.File))
	seen := make(map[string]bool)
	var candidates []*UnifiedNode
	appendCandidates := func(nodes []*UnifiedNode) {
		for _, node := range nodes {
			if node == nil || seen[node.Key] {
				continue
			}
			pos, ok := parseSourcePosition(node.Pos)
			if !ok {
				continue
			}
			if filepath.Clean(pos.File) != file || pos.Line != callInfo.Line {
				continue
			}
			if callInfo.Col > 0 && pos.Col != callInfo.Col {
				continue
			}
			seen[node.Key] = true
			candidates = append(candidates, node)
		}
	}

	if callInfo.Col > 0 {
		appendCandidates(lookup.byPosExact[sourcePositionKey(file, callInfo.Line, callInfo.Col)])
	}
	if len(candidates) == 0 {
		appendCandidates(lookup.byPosLine[sourcePositionKey(file, callInfo.Line, 0)])
	}

	return candidates
}

func edgeMatchesExtraTarget(edge *UnifiedEdge, target ExtraCallTarget, mainPkg string) bool {
	if edge == nil || edge.Callee == nil || edge.VTA == nil || !edge.VTA.HasSite {
		return false
	}
	if target.CallsiteLine > 0 && edge.VTA.SiteLine != target.CallsiteLine {
		return false
	}
	if target.CallsiteCol > 0 && edge.VTA.SiteCol != target.CallsiteCol {
		return false
	}

	node, reason := matchCandidateSet([]*UnifiedNode{edge.Callee}, target, mainPkg)
	if node == nil {
		return false
	}
	switch reason {
	case "alias-match", "normalized-generic-match", "canonical-match", "callsite-loose-match":
		return true
	default:
		return false
	}
}

func callerSpecificityScore(node *UnifiedNode) int {
	if node == nil {
		return -1
	}

	score := len(node.Key)
	if node.IsAnonymous {
		score += 1000
	}
	score += strings.Count(node.Key, "$") * 100
	if strings.Contains(node.Key, "[") {
		score += 40
	}
	return score
}

func resolveCallerNodeFromSource(callInfo CallInfo, unified *UnifiedCallGraph, mainPkg string) *UnifiedNode {
	candidates := callerSourceCandidates(callInfo, unified)
	if len(candidates) == 0 {
		return nil
	}

	bestMatchCount := -1
	bestScore := -1
	var best *UnifiedNode
	ambiguous := false

	for _, node := range candidates {
		matchCount := 0
		for _, target := range callInfo.Callee {
			for _, edge := range node.Out {
				if edgeMatchesExtraTarget(edge, target, mainPkg) {
					matchCount++
					break
				}
			}
		}

		score := callerSpecificityScore(node)
		if matchCount > bestMatchCount || (matchCount == bestMatchCount && score > bestScore) {
			best = node
			bestMatchCount = matchCount
			bestScore = score
			ambiguous = false
			continue
		}
		if matchCount == bestMatchCount && score == bestScore && best != nil && best.Key != node.Key {
			ambiguous = true
		}
	}

	if bestMatchCount > 0 && !ambiguous {
		return best
	}
	if bestMatchCount == 0 && len(candidates) == 1 {
		return candidates[0]
	}
	return nil
}

func getCallerNode(funcName string, callInfo CallInfo, unified *UnifiedCallGraph, mainPkg string) *UnifiedNode {
	_, caller := utils.ParseRuntimeNameWithMainPkg(funcName, mainPkg)
	callerNode := unified.Nodes[caller]
	if callerNode != nil {
		return callerNode
	}

	if callerNode := resolveCallerNodeFromSource(callInfo, unified, mainPkg); callerNode != nil {
		extraCallerCache[funcName] = callerNode.Key
		return callerNode
	}

	caller = extraCallerCache[funcName]
	if caller == "" && callInfo.CallerPathWithLine() != "" {
		ssaFunc, err := getSSAFunctionFallback(callInfo.CallerPathWithLine())
		if err == nil && ssaFunc != nil {
			caller = ssaFunc.String()
			extraCallerCache[funcName] = caller
		}
	}
	if caller == "" {
		// Unresolved callers are reported during preloading.
		return nil
	}

	callerNode = unified.Nodes[caller]
	if callerNode == nil {
		// Unresolved callers are reported during preloading.
		return nil
	}
	return callerNode
}

func isUnsupportedExtraRuntimeName(runtimeName string) bool {
	return strings.HasPrefix(runtimeName, "type:")
}

func extraRuntimeNameCandidates(runtimeName string, mainPkg string) []runtimeNameCandidate {
	if isUnsupportedExtraRuntimeName(runtimeName) {
		return nil
	}

	seen := make(map[string]bool)
	var candidates []runtimeNameCandidate

	addCandidate := func(pkgPath string, ssaName string) {
		if pkgPath == "" || ssaName == "" {
			return
		}
		key := pkgPath + "\x00" + ssaName
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, runtimeNameCandidate{
			PkgPath: pkgPath,
			SSAName: ssaName,
		})
	}

	pkgPath, ssaName := utils.ParseRuntimeNameWithMainPkg(runtimeName, mainPkg)
	addCandidate(pkgPath, ssaName)

	if strings.HasSuffix(ssaName, "-fm") {
		base := strings.TrimSuffix(ssaName, "-fm")
		addCandidate(pkgPath, base)
		addCandidate(pkgPath, base+"$bound")
	}

	if strings.HasSuffix(ssaName, "$bound") {
		addCandidate(pkgPath, strings.TrimSuffix(ssaName, "$bound"))
	}

	return candidates
}

func stripBracketContent(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}

	return b.String()
}

func normalizeBracketContent(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
			b.WriteByte(s[i])
		case ']':
			if depth > 0 {
				depth--
			}
			b.WriteByte(s[i])
		case ' ', '\t', '\n', '\r', ',':
			if depth > 0 {
				continue
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}

func normalizedFuncName(s string) string {
	s = strings.ReplaceAll(s, "-fm", "$bound")
	s = strings.ReplaceAll(s, "go.shape.", "")
	s = strings.ReplaceAll(s, "interface {}", "interface{}")
	s = strings.ReplaceAll(s, "interface{}", "any")
	return normalizeBracketContent(s)
}

func canonicalFuncName(s string) string {
	return stripBracketContent(normalizedFuncName(s))
}

func functionTail(s string) string {
	if idx := strings.LastIndex(s, ")."); idx != -1 {
		return s[idx+2:]
	}
	if idx := strings.LastIndex(s, "."); idx != -1 {
		return s[idx+1:]
	}
	return s
}

func stripClosureOrdinals(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}

		b.WriteByte('$')
		for i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
		}
	}

	return b.String()
}

func looseFuncName(s string) string {
	s = canonicalFuncName(s)
	s = strings.ReplaceAll(s, "$bound", "")
	return stripClosureOrdinals(functionTail(s))
}

func callsiteCandidates(callerNode *UnifiedNode, target ExtraCallTarget) []*UnifiedNode {
	if callerNode == nil {
		return nil
	}

	seen := make(map[string]bool)
	var candidates []*UnifiedNode
	for _, edge := range callerNode.Out {
		if edge == nil || edge.Callee == nil || edge.VTA == nil || !edge.VTA.HasSite {
			continue
		}
		if target.CallsiteLine > 0 && edge.VTA.SiteLine != target.CallsiteLine {
			continue
		}
		if target.CallsiteCol > 0 && edge.VTA.SiteCol != target.CallsiteCol {
			continue
		}
		if seen[edge.Callee.Key] {
			continue
		}
		seen[edge.Callee.Key] = true
		candidates = append(candidates, edge.Callee)
	}

	return candidates
}

func matchCandidateSet(candidates []*UnifiedNode, target ExtraCallTarget, mainPkg string) (*UnifiedNode, string) {
	if len(candidates) == 0 {
		return nil, ""
	}

	nameSet := make(map[string]bool)
	normalizedSet := make(map[string]bool)
	canonicalSet := make(map[string]bool)
	for _, candidate := range extraRuntimeNameCandidates(target.RuntimeName, mainPkg) {
		nameSet[candidate.SSAName] = true
		normalizedSet[normalizedFuncName(candidate.SSAName)] = true
		canonicalSet[canonicalFuncName(candidate.SSAName)] = true
	}

	for _, node := range candidates {
		if nameSet[node.Key] {
			return node, "alias-match"
		}
	}

	var normalizedMatches []*UnifiedNode
	for _, node := range candidates {
		if normalizedSet[normalizedFuncName(node.Key)] {
			normalizedMatches = append(normalizedMatches, node)
		}
	}
	if len(normalizedMatches) == 1 {
		return normalizedMatches[0], "normalized-generic-match"
	}

	var canonicalMatches []*UnifiedNode
	for _, node := range candidates {
		if canonicalSet[canonicalFuncName(node.Key)] {
			canonicalMatches = append(canonicalMatches, node)
		}
	}
	if len(canonicalMatches) == 1 {
		return canonicalMatches[0], "canonical-match"
	}

	targetLoose := looseFuncName(target.RuntimeName)
	var looseMatches []*UnifiedNode
	for _, node := range candidates {
		if looseFuncName(node.Key) == targetLoose {
			looseMatches = append(looseMatches, node)
		}
	}
	if len(looseMatches) == 1 {
		return looseMatches[0], "callsite-loose-match"
	}

	if len(candidates) == 1 {
		return candidates[0], "callsite-unique-fallback"
	}

	return nil, ""
}

func findUniqueGlobalCallee(target ExtraCallTarget, unified *UnifiedCallGraph, mainPkg string) (*UnifiedNode, string) {
	normalizedSet := make(map[string]bool)
	canonicalSet := make(map[string]bool)
	for _, candidate := range extraRuntimeNameCandidates(target.RuntimeName, mainPkg) {
		normalizedSet[normalizedFuncName(candidate.SSAName)] = true
		canonicalSet[canonicalFuncName(candidate.SSAName)] = true
	}

	var normalizedMatches []*UnifiedNode
	for _, node := range unified.Nodes {
		if normalizedSet[normalizedFuncName(node.Key)] {
			normalizedMatches = append(normalizedMatches, node)
		}
	}
	if len(normalizedMatches) == 1 {
		return normalizedMatches[0], "global-normalized-generic-match"
	}

	var matches []*UnifiedNode
	for _, node := range unified.Nodes {
		if canonicalSet[canonicalFuncName(node.Key)] {
			matches = append(matches, node)
		}
	}
	if len(matches) == 1 {
		return matches[0], "global-canonical-match"
	}

	return nil, ""
}

func resolveCalleeNode(callerOrig string, callInfo CallInfo, callerNode *UnifiedNode, target ExtraCallTarget, unified *UnifiedCallGraph, mainPkg string) (*UnifiedNode, string) {
	cacheKey := target.cacheKey(callerOrig)
	if cached := extraCalleeCache[cacheKey]; cached != "" {
		if node := unified.Nodes[cached]; node != nil {
			return node, "cache-hit"
		}
	}

	for _, candidate := range extraRuntimeNameCandidates(target.RuntimeName, mainPkg) {
		if node := unified.Nodes[candidate.SSAName]; node != nil {
			extraCalleeCache[cacheKey] = node.Key
			return node, "alias-match"
		}
	}

	if node, reason := matchCandidateSet(callsiteCandidates(callerNode, target), target, mainPkg); node != nil {
		extraCalleeCache[cacheKey] = node.Key
		return node, reason
	}

	if node, reason := findUniqueGlobalCallee(target, unified, mainPkg); node != nil {
		extraCalleeCache[cacheKey] = node.Key
		return node, reason
	}

	return nil, ""
}

func AddExtraEdge(unified *UnifiedCallGraph, extraEdges map[string]CallInfo, mainPkg string) {
	mainPkg = canonicalMainPkgFromCache(mainPkg)

	for callerOrig, callInfo := range extraEdges {
		callerNode := getCallerNode(callerOrig, callInfo, unified, mainPkg)
		if callerNode == nil {
			continue
		}
		if suppressedExtraEdgeCallers[callerNode.Key] {
			continue
		}
		for _, callee := range callInfo.Callee {
			calleeNode, _ := resolveCalleeNode(callerOrig, callInfo, callerNode, callee, unified, mainPkg)
			if calleeNode == nil {
				// Unresolved callees are reported during preloading.
				continue
			}
			if hasRetainedUnifiedEdge(callerNode, calleeNode) {
				continue
			}
			unified.AddEdge(callerNode, calleeNode, nil, "EXTRA")
		}
	}
}
