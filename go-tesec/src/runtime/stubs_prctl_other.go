// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(linux && amd64)

package runtime

func prctl(option int32, arg2, arg3, arg4, arg5 uintptr) int32 {
	return -1
}
