//go:build linux

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

const sysdigTracePrefix = "/tmp/go-exec-trace."

var sysdigTraceFD int32 = -1
var sysdigTracePath [64]byte
var sysdigTracePathLen int

// maybeStartSysdig starts sysdig if enabled by runtime configuration.
// This is Linux-only and is a no-op unless explicitly enabled.
func maybeStartSysdig() {
	if !sysdigEnabled() {
		return
	}
	sysdigLog("enabled")
	startSysdig()
}

func sysdigEnabled() bool {
	if v := gogetenv("GOSYSDIG_CHILD"); v != "" {
		// Child processes are disabled by default to avoid recursive tracing.
		// Set GOSYSDIG_CHILD_TRACE=1 to explicitly enable tracing in children.
		if v := gogetenv("GOSYSDIG_CHILD_TRACE"); v != "" && v != "0" {
			return true
		}
		return false
	}
	if v := gogetenv("GOSYSDIG"); v != "" && v != "0" {
		return true
	}
	if v := godebugValue(gogetenv("GODEBUG"), "gosysdig"); v == "1" {
		return true
	}
	return false
}

func sysdigLog(msg string) {
	writeErrStr("gosysdig: " + msg + "\n")
}

func godebugValue(env, key string) string {
	for len(env) > 0 {
		seg := env
		if i := indexByte(env, ','); i >= 0 {
			seg = env[:i]
			env = env[i+1:]
		} else {
			env = ""
		}
		if len(seg) > len(key) && seg[len(key)] == '=' && seg[:len(key)] == key {
			return seg[len(key)+1:]
		}
	}
	return ""
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func initSysdigTraceFD() {
	if sysdigTraceFD >= 0 {
		return
	}

	pid := getpid()
	var tmp [20]byte
	pidb := itoa(tmp[:], uint64(pid))

	copy(sysdigTracePath[:], sysdigTracePrefix)
	if len(sysdigTracePrefix)+len(pidb)+1 > len(sysdigTracePath) {
		return
	}
	copy(sysdigTracePath[len(sysdigTracePrefix):], pidb)
	pathLen := len(sysdigTracePrefix) + len(pidb)
	sysdigTracePath[pathLen] = 0
	fd := open(&sysdigTracePath[0], _O_WRONLY|_O_CREAT|_O_TRUNC|_O_CLOEXEC, 0600)
	if fd < 0 {
		sysdigLog("trace fd open failed")
		return
	}
	sysdigTraceFD = fd
	sysdigTracePathLen = pathLen
	sysdigLog("trace fd ready")
}

func SysdigTraceActive() bool {
	return sysdigTraceFD >= 0
}

func SysdigWrite(data []byte) {
	if sysdigTraceFD < 0 || len(data) == 0 {
		return
	}
	write1(uintptr(sysdigTraceFD), unsafe.Pointer(&data[0]), int32(len(data)))
}
