// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && amd64

package runtime

// prctl invokes the Linux prctl system call.
// The return value is the raw syscall result, which may encode an errno.
//
//go:noescape
func prctl(option int32, arg2, arg3, arg4, arg5 uintptr) int32
