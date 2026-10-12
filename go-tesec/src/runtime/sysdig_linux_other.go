//go:build linux && !amd64

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// startSysdig is not implemented on non-amd64 Linux yet.
func startSysdig() {}
