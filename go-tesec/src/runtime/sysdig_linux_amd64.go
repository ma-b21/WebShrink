//go:build linux && amd64

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/runtime/exithook"
	rtsyscall "internal/runtime/syscall"
	"unsafe"
)

const (
	sysdigOutputPrefix = "/tmp/go-sysdig."
	sysdigOutputSuffix = ".scap"
	sysdigPath         = "/usr/bin/sysdig"
	sudoPath           = "/usr/bin/sudo"
	sysdigSigterm      = 15
)

var sysdigPid int32
var sysdigExitHookAdded bool

func startSysdig() {
	initSysdigTraceFD()
	if sysdigTraceFD < 0 || sysdigTracePathLen == 0 {
		sysdigLog("trace fd not ready")
		return
	}

	pid := getpid()
	var tmp [20]byte
	pidb := itoa(tmp[:], uint64(pid))
	pidStr := string(pidb)

	tracePath := string(sysdigTracePath[:sysdigTracePathLen])
	filter := "(proc.apid=" + pidStr + " and proc.pid!=" + pidStr + " and proc.name!=sysdig) or (evt.type=write and fd.name=" + tracePath + ")"

	outPath := sysdigOutputPrefix + pidStr + sysdigOutputSuffix

	argv := []string{
		"sudo",
		"-n",
		sysdigPath,
		"-w",
		outPath,
		filter,
	}

	env := environ()
	pidFork, errno := sysdigForkExec(sudoPath, argv, env)
	if errno != 0 {
		sysdigLog("fork/exec failed errno=" + itoaStr(uint64(errno)))
		return
	}
	setSysdigPid(int32(pidFork))
	sysdigLog("sysdig started pid=" + itoaStr(uint64(pidFork)) + " out=" + outPath)
}

func sysdigForkExec(path string, argv []string, env []string) (uintptr, uintptr) {
	const sysPipe2 = 293
	const sysRead = 0
	const sysWrite = 1
	const sysWait4 = 61
	const sysFcntl = 72
	const fSetfd = 2
	const fdCloexec = 1

	argvp := make([]unsafe.Pointer, len(argv)+1)
	for i := range argv {
		argvp[i] = cstring(argv[i])
	}
	argvp[len(argv)] = nil

	var envp []unsafe.Pointer
	if len(env) > 0 {
		envp = make([]unsafe.Pointer, len(env)+1)
		for i := range env {
			envp[i] = cstring(env[i])
		}
		envp[len(env)] = nil
	} else {
		envp = []unsafe.Pointer{nil}
	}

	// Create a pipe for execve error reporting.
	// Child writes errno byte on execve failure; parent reads to detect it.
	// On successful exec the write end is closed by O_CLOEXEC, so parent
	// sees EOF immediately.
	var pipefd [2]int32
	_, _, e1 := rtsyscall.Syscall6(sysPipe2, uintptr(unsafe.Pointer(&pipefd[0])), 0, 0, 0, 0, 0)
	if e1 != 0 {
		return 0, uintptr(e1)
	}
	// Set CLOEXEC on write end so execve closes it automatically.
	rtsyscall.Syscall6(sysFcntl, uintptr(pipefd[1]), fSetfd, fdCloexec, 0, 0, 0)

	syscall_runtime_BeforeFork()
	pid, _, errno := rtsyscall.Syscall6(rtsyscall.SYS_FORK, 0, 0, 0, 0, 0, 0)
	if errno != 0 {
		syscall_runtime_AfterFork()
		rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[0]), 0, 0, 0, 0, 0)
		rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[1]), 0, 0, 0, 0, 0)
		return 0, errno
	}
	if pid == 0 {
		syscall_runtime_AfterForkInChild()
		// Child: close read end.
		rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[0]), 0, 0, 0, 0, 0)
		_, _, _ = rtsyscall.Syscall6(rtsyscall.SYS_PRCTL, rtsyscall.PR_SET_PDEATHSIG, uintptr(sysdigSigterm), 0, 0, 0, 0)
		_, _, e2 := rtsyscall.Syscall6(rtsyscall.SYS_EXECVE,
			uintptr(cstring(path)),
			uintptr(unsafe.Pointer(&argvp[0])),
			uintptr(unsafe.Pointer(&envp[0])),
			0, 0, 0)
		// execve failed — send errno byte to parent, then exit.
		var errnoBuf [1]byte
		errnoBuf[0] = byte(e2)
		rtsyscall.Syscall6(sysWrite, uintptr(pipefd[1]), uintptr(unsafe.Pointer(&errnoBuf[0])), 1, 0, 0, 0)
		rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[1]), 0, 0, 0, 0, 0)
		rtsyscall.Syscall6(rtsyscall.SYS_EXIT, 127, 0, 0, 0, 0, 0)
		return 0, 0
	}
	syscall_runtime_AfterFork()

	// Parent: close write end.
	rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[1]), 0, 0, 0, 0, 0)

	// Read from pipe. If execve succeeded, write end is closed by O_CLOEXEC
	// and we get EOF (n=0). If execve failed, we get 1 byte with the errno.
	var errnoBuf [1]byte
	n, _, _ := rtsyscall.Syscall6(sysRead, uintptr(pipefd[0]), uintptr(unsafe.Pointer(&errnoBuf[0])), 1, 0, 0, 0)
	rtsyscall.Syscall6(rtsyscall.SYS_CLOSE, uintptr(pipefd[0]), 0, 0, 0, 0, 0)

	if n > 0 {
		// execve failed; wait for child to exit then report the errno.
		rtsyscall.Syscall6(sysWait4, uintptr(pid), 0, 0, 0, 0, 0)
		return 0, uintptr(errnoBuf[0])
	}

	return pid, 0
}

func setSysdigPid(pid int32) {
	if pid <= 0 || sysdigPid != 0 {
		return
	}
	sysdigPid = pid
	if !sysdigExitHookAdded {
		sysdigExitHookAdded = true
		exithook.Add(exithook.Hook{F: sysdigExitHook, RunOnFailure: true})
	}
}

func sysdigExitHook() {
	pid := sysdigPid
	if pid <= 0 {
		return
	}
	_, _, _ = rtsyscall.Syscall6(rtsyscall.SYS_KILL, uintptr(pid), uintptr(sysdigSigterm), 0, 0, 0, 0)
}

func itoaStr(v uint64) string {
	var tmp [20]byte
	return string(itoa(tmp[:], v))
}
