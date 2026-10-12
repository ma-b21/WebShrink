//go:build !linux

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

func maybeWriteSysdigStack(childPid int) {}

func maybeAppendSysdigChildEnv(env []string) []string { return env }
