//go:build linux

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"runtime"
	"strconv"
	"strings"
	"time"
)

func maybeWriteSysdigStack(childPid int) {
	if !runtime.SysdigTraceActive() {
		return
	}
	const maxFrames = 64
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	var b strings.Builder
	b.Grow(512)
	b.WriteString("GOEXECSTACK ts=")
	b.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10))
	b.WriteString(" pid=")
	b.WriteString(strconv.Itoa(childPid))
	b.WriteByte('\n')

	for {
		frame, more := frames.Next()
		// Clean up the function name to remove redundant caller information.
		// runtime.CallersFrames may return names like:
		// "pkg.(*T).CallerMethod.(*T).ActualFunc.closureN"
		// where the first part is the caller, not the actual function.
		// We keep only the last method/closure chain: "(*T).ActualFunc.closureN"
		funcName := cleanFuncName(frame.Function)
		b.WriteString(funcName)
		b.WriteByte('\n')
		b.WriteString(frame.File)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(frame.Line))
		b.WriteByte('\n')
		if !more {
			break
		}
	}
	b.WriteByte('\n')

	runtime.SysdigWrite([]byte(b.String()))
}

// cleanFuncName removes redundant caller information from function names.
// When runtime.CallersFrames returns names like:
// "pkg.(*T).CallerMethod.(*T).ActualFunc.closureN"
// this function extracts the package path and the last method/closure chain:
// "pkg.(*T).ActualFunc.closureN"
//
// It detects the pattern where there are multiple method receivers "(*T)"
// and keeps only the package path plus the last one along with its function name.
// For normal function names without multiple receivers, it returns unchanged.
func cleanFuncName(fullName string) string {
	// Find the first method receiver to get the package path
	firstReceiver := strings.Index(fullName, "(*")
	if firstReceiver < 0 {
		// No method receiver, return as-is (plain function)
		return fullName
	}

	// Check if there's a second method receiver after the first one
	afterFirst := fullName[firstReceiver:]
	secondReceiver := strings.Index(afterFirst[2:], "(*")
	if secondReceiver < 0 {
		// Only one method receiver, return as-is (includes package path)
		return fullName
	}

	// Multiple receivers found: extract package path and last method chain
	// Package path is everything before the first "(*"
	pkgPath := fullName[:firstReceiver]

	// Last method chain starts from the last "(*"
	lastReceiver := strings.LastIndex(fullName, "(*")
	lastMethodChain := fullName[lastReceiver:]

	return pkgPath + lastMethodChain
}

func maybeAppendSysdigChildEnv(env []string) []string {
	if !runtime.SysdigTraceActive() {
		return env
	}
	if envHasKey(env, "GOSYSDIG_CHILD") {
		return env
	}
	return append(env, "GOSYSDIG_CHILD=1")
}

func envHasKey(env []string, key string) bool {
	for _, kv := range env {
		if len(kv) > len(key) && kv[len(key)] == '=' && kv[:len(key)] == key {
			return true
		}
	}
	return false
}
