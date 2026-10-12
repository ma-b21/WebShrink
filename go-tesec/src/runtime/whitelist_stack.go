// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

// whitelistStack stores a small stack of whitelist identifiers associated with a
// goroutine. It optimizes for the common case where the nesting depth is small
// by keeping a fixed number of elements inline before spilling to a heap-allocated
// slice. The stack is not concurrency-safe and is expected to be mutated only by
// the currently executing goroutine or the runtime scheduler when switching
// goroutines.
const whitelistInlineCapacity = 4

type whitelistStack struct {
	// depth tracks the number of elements currently stored. A zero depth means
	// the stack is empty.
	depth int32

	// inline stores the first whitelistInlineCapacity elements without additional
	// allocations.
	inline [whitelistInlineCapacity]uint32

	// overflow holds elements beyond the inline capacity. The slice is kept to
	// reuse capacity across pushes.
	overflow []uint32
}

// reset clears the stack but retains any allocated overflow capacity for reuse.
func (s *whitelistStack) reset() {
	s.depth = 0
	if len(s.overflow) != 0 {
		s.overflow = s.overflow[:0]
	}
}

// empty reports whether the stack holds no elements.
func (s *whitelistStack) empty() bool {
	return s.depth == 0
}

// push adds id to the top of the stack.
func (s *whitelistStack) push(id uint32) {
	if s.depth < whitelistInlineCapacity {
		s.inline[s.depth] = id
	} else {
		extraIdx := int(s.depth - whitelistInlineCapacity)
		if extraIdx < len(s.overflow) {
			s.overflow[extraIdx] = id
		} else {
			s.overflow = append(s.overflow, id)
		}
	}
	s.depth++
}

// pop removes and returns the top element of the stack. The boolean result is
// false if the stack was empty.
func (s *whitelistStack) pop() (uint32, bool) {
	if s.depth == 0 {
		return 0, false
	}

	s.depth--
	idx := s.depth
	if idx < whitelistInlineCapacity {
		return s.inline[idx], true
	}

	extraIdx := int(idx - whitelistInlineCapacity)
	val := s.overflow[extraIdx]
	if extraIdx+1 == len(s.overflow) {
		// Keep the allocated buffer but drop the logical length.
		s.overflow = s.overflow[:extraIdx]
	}
	return val, true
}

// current returns the top element without modifying the stack. The boolean
// result is false if the stack is empty.
func (s *whitelistStack) current() (uint32, bool) {
	if s.depth == 0 {
		return 0, false
	}

	idx := s.depth - 1
	if idx < whitelistInlineCapacity {
		return s.inline[idx], true
	}

	extraIdx := int(idx - whitelistInlineCapacity)
	return s.overflow[extraIdx], true
}

// profileSwitchMagic is the prctl option understood by the trusted runtime shim
// and forwarded to eBPF for per-thread profile switching.
const profileSwitchMagic = int32(0x1234face)

// profileFloorMagic is the prctl option to set the per-process floor profile.
// Once set, the eBPF layer prevents the effective profile from dropping
// below this floor, even when the per-thread profile is 0.
const profileFloorMagic = int32(0x1234facf)

// Shared memory constants for fast whitelist switching.
// The shared memory layout is:
//   [0:8]   uint64  array base address (written by Go runtime)
//   [8:]    uint32[] whitelist ID array, indexed by TID
//
// The Go runtime writes the array base address to the first 8 bytes,
// then writes whitelist IDs directly to the array. The eBPF program
// reads from the array via bpf_probe_read_user(), eliminating the
// need for a prctl() syscall on every whitelist switch.
const (
	shmemAddrSize  = 8                          // size of the address field
	shmemMaxTid    = 1 << 22                     // max TID (4194304)
	shmemArraySize = shmemMaxTid * 4             // uint32 per TID
	shmemTotalSize = shmemAddrSize + shmemArraySize // total file size
)

// shmemBase is the mmap'd base address of the shared memory region.
// shmemArrayBase is shmemBase + 8, pointing to the start of the TID-indexed array.
// When non-nil, switchWhitelist writes directly to shared memory instead of prctl.
var (
	shmemBase      unsafe.Pointer
	shmemArrayBase unsafe.Pointer
)

// baseProfile stores the inherited profile read at init.
// A value of 0 means no base profile was set.
var baseProfile uint32

//go:nosplit
func gpushWhitelist(gp *g, id uint32) {
	if gp == nil {
		panic("gpushWhitelist: g is nil")
	}

	prev, hadPrev := gp.whitelist.current()
	gp.whitelist.push(id)
	if !hadPrev || prev != id {
		switchWhitelist(id)
	}
}

//go:nosplit
func gpopWhitelist(gp *g) bool {
	if gp == nil {
		panic("gpopWhitelist: g is nil")
	}

	popped, ok := gp.whitelist.pop()
	if !ok {
		return false
	}

	newID := uint32(0)
	if current, has := gp.whitelist.current(); has {
		newID = current
	}

	if newID != popped {
		switchWhitelist(newID)
	}

	return true
}

//go:nosplit
func switchWhitelist(id uint32) {
	if shmemArrayBase != nil {
		// Fast path: write directly to shared memory indexed by TID.
		tid := uint32(getg().m.procid)
		*(*uint32)(add(shmemArrayBase, uintptr(tid)*4)) = id
	} else {
		// Fallback: use prctl to communicate with eBPF.
		prctl(profileSwitchMagic, uintptr(id), 0, 0, 0)
	}
}

// PushWhitelist records id as the active whitelist for the current goroutine.
// Calls nest, forming a stack that propagates across goroutine scheduling
// points.
//
//go:nosplit
//go:linkname PushWhitelist
func PushWhitelist(id uint32) {
	gp := currentWhitelistG()
	gpushWhitelist(gp, id)
}

// PopWhitelist removes the most recently pushed whitelist for the current
// goroutine. It returns false if the stack was already empty. When the stack
// becomes empty the runtime switches back to the default whitelist (id==0).
//
//go:nosplit
//go:linkname PopWhitelist
func PopWhitelist() bool {
	gp := currentWhitelistG()
	return gpopWhitelist(gp)
}

//go:nosplit
func currentWhitelistG() *g {
	gp := getg()
	if gp == nil {
		throw("currentWhitelistG: nil g")
	}

	if gp.m != nil && gp == gp.m.g0 && gp.m.curg != nil {
		gp = gp.m.curg
	}

	return gp
}

// switchToWhitelistOf switch current M to gp's current whitelist if exists
func switchToWhitelistOf(gp *g) {
	whitelist, exists := gp.whitelist.current()
	if !exists {
		switchWhitelist(0)
		return
	}
	switchWhitelist(whitelist)
}

// cancelWhitelist switch current M to whitelist 0 (no restrict)
func cancelWhitelist() {
	switchWhitelist(0)
}

// setProfileFloor sets the process-wide profile floor via prctl.
// Once set, the eBPF layer prevents the effective profile from dropping
// below this floor, even when cancelWhitelist clears the per-thread profile.
func setProfileFloor(id uint32) {
	prctl(profileFloorMagic, uintptr(id), 0, 0, 0)
}

// initBaseProfile reads the WSHRINK_PROFILE environment variable and,
// if set, configures the profile floor and pushes the profile onto the
// main goroutine's whitelist stack. This allows a parent process to
// preset the profile for a child that would otherwise start at profile 0.
func initBaseProfile() {
	v := gogetenv("WSHRINK_PROFILE")
	if v == "" {
		return
	}
	// Parse the profile ID from the environment variable.
	id := uint32(0)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < '0' || c > '9' {
			return
		}
		id = id*10 + uint32(c-'0')
	}
	if id == 0 || id > MAX_PROFILE_ID {
		return
	}

	baseProfile = id
	// Set the kernel-level floor so that even when cancelWhitelist
	// resets the per-thread profile to 0, enforcement stays at this level.
	setProfileFloor(id)
	// Push onto the main goroutine so cooperative scheduling also
	// restores this profile correctly.
	PushWhitelist(id)
}

// MAX_PROFILE_ID for the Go runtime side, must match the eBPF definition.
const MAX_PROFILE_ID = 197

// shmemInit initializes the shared memory region for fast whitelist switching.
// It reads WSHRINK_SHMEM_PATH from the environment. If set, it creates the
// shared memory file, mmaps it, and writes the array base address to the
// first 8 bytes. The eBPF loader polls this file to discover the address.
//
// This must be called before initBaseProfile() so that PushWhitelist can
// use the fast path.
func shmemInit() {
	path := gogetenv("WSHRINK_SHMEM_PATH")
	if path == "" {
		return
	}

	// Convert path to a C string for the open syscall.
	pathBytes := []byte(path)
	pathBytes = append(pathBytes, 0)
	pathPtr := &pathBytes[0]

	// Open or create the shared memory file.
	//
	// Do not use O_TRUNC here. A protected Go process may exec another
	// go-tesec-linked binary that inherits the same WSHRINK_SHMEM_PATH.
	// Truncating the already-mapped file would briefly shrink it to size 0,
	// which can SIGBUS sibling threads still writing cancelWhitelist() to the
	// existing mapping in the parent process.
	fd := open(pathPtr, _O_RDWR|_O_CREAT, 0600)
	if fd < 0 {
		return
	}

	// Set the file size.
	if ftruncate(fd, shmemTotalSize) < 0 {
		closefd(fd)
		return
	}

	// Map the file into memory.
	p, err := mmap(nil, shmemTotalSize, _PROT_READ|_PROT_WRITE, _MAP_SHARED, fd, 0)
	closefd(fd)
	if err != 0 {
		return
	}

	shmemBase = p
	shmemArrayBase = add(p, shmemAddrSize)

	// Write the array base address to the first 8 bytes.
	// The eBPF loader polls this to discover the address.
	*(*uintptr)(shmemBase) = uintptr(shmemArrayBase)
}
