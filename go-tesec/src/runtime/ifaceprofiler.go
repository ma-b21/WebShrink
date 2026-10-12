// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"internal/runtime/exithook"
	"unsafe"
)

// RecordIfaceCall records a unique interface call site and the dynamic type
// of the receiver. It is intended for offline whitelist generation and is
// enabled only when the compiler emits the call.
func RecordIfaceCall(file string, line int, col int, caller string, method string, tab *uintptr) {
	if tab == nil {
		return
	}
	it := (*itab)(unsafe.Pointer(tab))
	record(ifaceLogKindIface, file, line, col, caller, method, it.Type, nil, 0)
}

// RecordReflectCall records a unique reflection-based function call site and target name.
func RecordReflectCall(file string, line int, col int, caller string, name string, typ *abi.Type) {
	if name == "" {
		return
	}
	record(ifaceLogKindReflect, file, line, col, caller, name, nil, typ, 0)
}

// RecordDynamicCall records a unique dynamic function-value call site and
// resolved target.
func RecordDynamicCall(file string, line int, col int, caller string, pc uintptr) {
	if pc == 0 {
		return
	}
	record(ifaceLogKindDynamic, file, line, col, caller, "", nil, nil, pc)
}

// --- Implementation Details ---

const (
	ifaceLogKindIface   = 1
	ifaceLogKindReflect = 2
	ifaceLogKindDynamic = 3

	// cacheSize is the size of the frontend deduplication cache.
	// Must be a power of 2.
	cacheSize = 1024

	// logBufferSize is the size of the channel buffer.
	logBufferSize = 4096

	// flushIntervalNs is 10 seconds in nanoseconds.
	flushIntervalNs = 10 * 1000 * 1000 * 1000
)

type ifaceLogRecord struct {
	kind   int8
	file   string
	line   int32
	col    int32
	caller string
	name   string
	typ    uintptr // *_type
	rtyp   uintptr // *abi.Type
	pc     uintptr
}

// enableIfaceLog is a flag to enable interface call logging.
// It is set to true by the compiler when -ifacelog flag is passed.
var enableIfaceLog bool

var (
	ifaceLogReady   atomic.Uint32 // 0=not ready, 1=ready, 2=closing
	ifaceLogCache   [cacheSize]atomic.Uint64
	ifaceLogCh      chan ifaceLogRecord
	ifaceLogFlushCh chan struct{}
	ifaceLogFD      int32 = -1
)

func record(kind int8, file string, line int, col int, caller string, name string, typ *_type, rtyp *abi.Type, pc uintptr) {
	// Avoid re-entrancy issues: if we are allocating memory, don't log.
	// Logging involves channel sends which can be risky in deep runtime paths.
	// Also avoid logging if we hold any locks, as channel operations can trigger
	// scheduler actions (goready) which require locks (sched.lock), leading to deadlock.
	// Finally, if we are dying (panicking), don't log to avoid deadlock during panic printing.
	// Also avoid logging on g0 or gsignal stacks.
	if gp := getg(); gp == nil || gp.m.mallocing > 0 || gp.m.locks > 0 || gp.m.dying > 0 || gp == gp.m.g0 || gp == gp.m.gsignal {
		return
	}

	// If not initialized or closing, drop the record.
	// We initialize explicitly in runtime.main if enableIfaceLog is true.
	if ifaceLogReady.Load() != 1 {
		return
	}

	// Frontend Deduplication (Lock-Free Cache)
	// We use a hash of the call site to check if we've seen this recently.
	filePtr := unsafe.StringData(file)
	var dataPtr uintptr
	switch kind {
	case ifaceLogKindIface:
		dataPtr = uintptr(unsafe.Pointer(typ))
	case ifaceLogKindReflect:
		dataPtr = uintptr(unsafe.Pointer(rtyp))
	default:
		dataPtr = pc
	}

	// Mix reflect target name into the hash so different targets at the
	// same call site are not suppressed by the frontend cache.
	var namePtr *byte
	if kind == ifaceLogKindReflect {
		namePtr = unsafe.StringData(name)
	}

	// Calculate a 64-bit hash for the entry.
	// We mix the file pointer, line, and type pointer.
	// We use a simple mixing function.
	h := uint64(uintptr(unsafe.Pointer(filePtr)))
	h ^= uint64(line) * 0x9e3779b97f4a7c15
	h ^= uint64(dataPtr) * 0xc6a4a7935bd1e995
	h ^= h >> 33

	if namePtr != nil {
		h ^= uint64(uintptr(unsafe.Pointer(namePtr))) * 0x85ebca6b
		h ^= uint64(len(name)) * 0xc2b2ae35
	}

	// Use part of the hash as the index.
	idx := h & (cacheSize - 1)

	// Check if the slot already contains this hash.
	// Load is atomic.
	if ifaceLogCache[idx].Load() == h {
		return
	}

	// Store the new hash.
	// This might overwrite another entry (collision), which is fine.
	// It might also race with another thread writing the same or different hash.
	// If we overwrite, we just send the record again.
	ifaceLogCache[idx].Store(h)

	// Send to backend
	// Non-blocking send to avoid stalling the application.
	rec := ifaceLogRecord{
		kind:   kind,
		file:   file,
		line:   int32(line),
		col:    int32(col),
		caller: caller,
		name:   name,
		typ:    uintptr(unsafe.Pointer(typ)),
		rtyp:   uintptr(unsafe.Pointer(rtyp)),
		pc:     pc,
	}

	select {
	case ifaceLogCh <- rec:
	default:
		// Channel full, drop record.
	}
}

func ifaceProfilerInit() {
	// Create channels
	ifaceLogCh = make(chan ifaceLogRecord, logBufferSize)
	// Keep one pending flush token so exit can always request at least
	// one flush without relying on a receiver rendezvous.
	ifaceLogFlushCh = make(chan struct{}, 1)

	// Open file
	name := "/tmp/ifacecalls.log\x00"
	fd := open(unsafe.StringData(name), _O_WRONLY|_O_CREAT|0x400, 0644) // O_APPEND
	if fd < 0 {
		ifaceLogFD = 2 // stderr
	} else {
		ifaceLogFD = fd
	}

	// Start background writer
	go ifaceLogWriter()

	// Start flush ticker
	go ifaceLogTicker()

	// Register exit hook
	exithook.Add(exithook.Hook{F: ifaceLogExit, RunOnFailure: true})

	ifaceLogReady.Store(1)
}

// ifaceLogExit is called when the program is exiting.
func ifaceLogExit() {
	// Signal writer to drain and exit.
	// We don't close the channel to avoid race with record().
	ifaceLogReady.Store(2)

	// Wake up writer to flush.
	if ifaceLogFlushCh != nil {
		// Guarantee there is at least one pending flush request.
		// If the channel is already full, a flush has already been queued.
		select {
		case ifaceLogFlushCh <- struct{}{}:
		default:
		}
	}

	// We can't easily wait for the writer in runtime without WaitGroup (which uses semaphores).
	// We'll just sleep a bit to give it a chance to flush.
	// Use usleep instead of timeSleep because the scheduler might be stopped at exit.
	usleep(200 * 1000) // 200ms
}

func ifaceLogTicker() {
	for {
		timeSleep(flushIntervalNs)
		// Non-blocking send to signal flush
		select {
		case ifaceLogFlushCh <- struct{}{}:
		default:
		}
	}
}

func ifaceLogWriter() {
	// Full deduplication map
	// Since this runs in a dedicated goroutine, we can use regular maps.
	seen := make(map[ifaceLogRecord]struct{})

	// Buffer for file writing
	var buf []byte
	const writeThreshold = 64 * 1024 // 64KB

	flush := func() {
		if len(buf) > 0 {
			writeLog(buf)
			buf = buf[:0]
		}
	}

	process := func(rec ifaceLogRecord) {
		// Deduplicate
		if _, ok := seen[rec]; ok {
			return
		}
		seen[rec] = struct{}{}

		// Format
		buf = formatIfaceLogRecord(buf, rec)

		if len(buf) > writeThreshold {
			flush()
		}
	}

	for {
		select {
		case rec := <-ifaceLogCh:
			process(rec)

		case <-ifaceLogFlushCh:
			flush()
			// Check if we are closing
			if ifaceLogReady.Load() == 2 {
				// Drain channel
				for {
					select {
					case rec := <-ifaceLogCh:
						process(rec)
					default:
						flush()
						return
					}
				}
			}
		}
	}
}

func formatIfaceLogRecord(buf []byte, rec ifaceLogRecord) []byte {
	buf = append(buf, '{')

	// kind
	buf = append(buf, '"', 'k', 'i', 'n', 'd', '"', ':')
	switch rec.kind {
	case ifaceLogKindIface:
		buf = append(buf, '"', 'i', 'f', 'a', 'c', 'e', '"')
	case ifaceLogKindReflect:
		buf = append(buf, '"', 'r', 'e', 'f', 'l', 'e', 'c', 't', '"')
	default:
		buf = append(buf, '"', 'd', 'y', 'n', 'a', 'm', 'i', 'c', '"')
	}

	// file
	buf = append(buf, ',')
	buf = appendJSONKeyString(buf, "file", rec.file)

	// line
	buf = append(buf, ',')
	buf = appendJSONKeyInt(buf, "line", int64(rec.line))

	// col
	buf = append(buf, ',')
	buf = appendJSONKeyInt(buf, "col", int64(rec.col))

	// caller
	buf = append(buf, ',')
	buf = appendJSONKeyString(buf, "caller", rec.caller)

	if rec.kind == ifaceLogKindIface {
		// method name
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "method", rec.name)

		// dynamic type name
		var typName string
		var typPkg string
		var typBase string
		if rec.typ != 0 {
			rt := toRType((*abi.Type)(unsafe.Pointer(rec.typ)))
			typName = rt.string()
			typPkg = rt.pkgpath()
			typBase = rt.name()
		}
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type", typName)
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_pkgpath", typPkg)
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_name", typBase)
	} else if rec.kind == ifaceLogKindReflect {
		// reflect target
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "func", rec.name)

		// reflected type name if available
		var rtypName string
		var rtypPkg string
		var rtypBase string
		if rec.rtyp != 0 {
			rt := toRType((*abi.Type)(unsafe.Pointer(rec.rtyp)))
			rtypName = rt.string()
			rtypPkg = rt.pkgpath()
			rtypBase = rt.name()
		}
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type", rtypName)
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_pkgpath", rtypPkg)
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_name", rtypBase)
	} else {
		// dynamic function-value target
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "func", dynamicCallName(rec.pc))

		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type", "")
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_pkgpath", "")
		buf = append(buf, ',')
		buf = appendJSONKeyString(buf, "type_name", "")
	}

	buf = append(buf, '}')
	buf = append(buf, '\n')
	return buf
}

func dynamicCallName(pc uintptr) string {
	if pc == 0 {
		return ""
	}
	f := FuncForPC(pc)
	if f == nil {
		return ""
	}
	return simplifyFuncName(f.Name())
}

// simplifyFuncName normalizes runtime function names for ifacelog.
//
// Rules:
//   - For regular symbols, keep only the bottom named function/method.
//   - If the bottom symbol is a method, keep receiver + method.
//   - Drop compiler-generated method-value wrapper suffix "-fm".
//   - For closure chains, append only the trailing .funcN(.funcM...) suffix.
//   - Drop compiler-generated outer named-function nesting.
//
// Examples:
//   - "pkg/path.f" -> "pkg/path.f"
//   - "pkg/path.Type.Method" -> "pkg/path.Type.Method"
//   - "pkg/path.(*Type).Method" -> "pkg/path.(*Type).Method"
//   - "pkg/path.(*Type).Method-fm" -> "pkg/path.(*Type).Method"
//   - "pkg/path.(*Type).Method.nested.func2" -> "pkg/path.nested.func2"
//   - "pkg/path.(*Type).Method.func1.func2" -> "pkg/path.(*Type).Method.func1.func2"
func simplifyFuncName(name string) string {
	if name == "" {
		return ""
	}

	pkg, sym := splitLinkFuncName(name)
	if pkg == "" || sym == "" {
		return name
	}

	parts := splitTopLevelSymbolParts(sym)
	if len(parts) == 0 {
		return name
	}

	// Keep only trailing closure suffix parts. In addition to plain
	// .funcN(.funcM...) chains, preserve compiler-style numeric continuation
	// suffixes attached to closures, e.g. .func1.1(.2...).
	suffixStart := len(parts)
	digitStart := suffixStart
	for digitStart > 0 && isNumericPart(parts[digitStart-1]) {
		digitStart--
	}
	if digitStart < suffixStart && digitStart > 0 && isClosurePart(parts[digitStart-1]) {
		// Include the closure segment that owns the numeric continuation,
		// and any contiguous closure chain immediately before it.
		suffixStart = digitStart - 1
		for suffixStart > 0 && isClosurePart(parts[suffixStart-1]) {
			suffixStart--
		}
	} else {
		for suffixStart > 0 && isClosurePart(parts[suffixStart-1]) {
			suffixStart--
		}
	}
	if suffixStart == 0 {
		return name
	}

	base := parts[suffixStart-1]
	if suffixStart >= 2 && isReceiverLikePart(parts[suffixStart-2]) {
		base = parts[suffixStart-2] + "." + trimMethodValueWrapperSuffix(parts[suffixStart-1])
	} else if suffixStart == 2 {
		// The bottom named symbol can be a method receiver + method,
		// or a compiler-generated two-part function name (e.g. init.0).
		// Keep both parts in either case.
		base = parts[0] + "." + trimMethodValueWrapperSuffix(parts[1])
	} else {
		base = trimMethodValueWrapperSuffix(base)
	}

	out := pkg + "." + base
	for i := suffixStart; i < len(parts); i++ {
		out += "." + parts[i]
	}
	return out
}

func splitTopLevelSymbolParts(sym string) []string {
	parts := make([]string, 0, 4)
	start := 0
	parenDepth := 0
	bracketDepth := 0

	for i := 0; i < len(sym); i++ {
		switch sym[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '.':
			if parenDepth == 0 && bracketDepth == 0 {
				parts = append(parts, sym[start:i])
				start = i + 1
			}
		}
	}

	parts = append(parts, sym[start:])
	return parts
}

func isClosurePart(part string) bool {
	if len(part) <= 4 {
		return false
	}
	if part[0] != 'f' || part[1] != 'u' || part[2] != 'n' || part[3] != 'c' {
		return false
	}
	for i := 4; i < len(part); i++ {
		if part[i] < '0' || part[i] > '9' {
			return false
		}
	}
	return true
}

func isNumericPart(part string) bool {
	if part == "" {
		return false
	}
	for i := 0; i < len(part); i++ {
		if part[i] < '0' || part[i] > '9' {
			return false
		}
	}
	return true
}

func isReceiverLikePart(part string) bool {
	if part == "" {
		return false
	}
	if part[0] == '*' || part[0] == '(' || part[len(part)-1] == ')' {
		return true
	}
	for i := 0; i < len(part); i++ {
		if part[i] == '[' || part[i] == ']' {
			return true
		}
	}
	return false
}

func trimMethodValueWrapperSuffix(sym string) string {
	if len(sym) >= 3 && sym[len(sym)-3:] == "-fm" {
		return sym[:len(sym)-3]
	}
	return sym
}

func splitLinkFuncName(name string) (pkgpath, sym string) {
	// Keep behavior aligned with compiler/ir splitPkg:
	// split at first '.' after the last '/' that appears before any
	// non-import-path character.
	lastSlashIdx := 0
	for i := 0; i < len(name); i++ {
		if !escapedImportPathByteOK(name[i]) {
			break
		}
		if name[i] == '/' {
			lastSlashIdx = i
		}
	}
	for i := lastSlashIdx; i < len(name); i++ {
		if name[i] == '.' {
			return name[:i], name[i+1:]
		}
	}
	return "", name
}

func escapedImportPathByteOK(b byte) bool {
	return modPathByteOK(b) || b == '+' || b == '/' || b == '%'
}

func modPathByteOK(b byte) bool {
	return b == '-' || b == '.' || b == '_' || b == '~' ||
		('0' <= b && b <= '9') ||
		('A' <= b && b <= 'Z') ||
		('a' <= b && b <= 'z')
}

func writeLog(p []byte) {
	if ifaceLogFD < 0 {
		return
	}
	for len(p) > 0 {
		n := write1(uintptr(ifaceLogFD), unsafe.Pointer(&p[0]), int32(len(p)))
		if n <= 0 {
			return
		}
		p = p[n:]
	}
}

// appendInt appends d in base-10.
func appendInt(dst []byte, v int64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	sign := v < 0
	if sign {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if sign {
		i--
		buf[i] = '-'
	}
	return append(dst, buf[i:]...)
}

// appendJSONKeyString appends a JSON string field with the given key and value.
func appendJSONKeyString(dst []byte, key string, val string) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, '"', ':')
	return appendJSONString(dst, val)
}

// appendJSONKeyInt appends a JSON int field with the given key and value.
func appendJSONKeyInt(dst []byte, key string, v int64) []byte {
	dst = append(dst, '"')
	dst = append(dst, key...)
	dst = append(dst, '"', ':')
	return appendInt(dst, v)
}

// appendJSONString appends val as a quoted JSON string with basic escaping.
func appendJSONString(dst []byte, val string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(val); i++ {
		c := val[i]
		switch c {
		case '\\', '"':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				// Control characters are emitted as \u00XX
				dst = append(dst, '\\', 'u', '0', '0')
				hex := "0123456789abcdef"
				dst = append(dst, hex[c>>4], hex[c&0xF])
				continue
			}
			dst = append(dst, c)
		}
	}
	dst = append(dst, '"')
	return dst
}
