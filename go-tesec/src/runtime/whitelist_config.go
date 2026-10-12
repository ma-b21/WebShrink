// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"unsafe"
)

// whitelistConfig stores the mapping from function names to whitelist IDs.
// It is populated during runtime initialization if a whitelist_config.json
// file is found in the working directory.
var whitelistConfig struct {
	// funcMap maps fully qualified function names to whitelist IDs.
	// Function names are in the format returned by runtime.FuncForPC().Name()
	// e.g., "main.myFunc" or "github.com/user/pkg.Function"
	funcMap map[string]uint32

	// loaded indicates whether a config file was successfully loaded
	loaded bool
}

const whitelistConfigFilename = "whitelist_config.json"

// loadWhitelistConfig attempts to load and parse the whitelist configuration
// file from the current working directory. This should be called during
// runtime initialization, before main.main() runs.
// If the file doesn't exist or cannot be parsed, it silently returns without
// error to avoid disrupting normal program execution.
func loadWhitelistConfig() {
	// Read the config file
	data, err := readWhitelistConfigFile(whitelistConfigFilename)
	if err != nil {
		// Config file not found or cannot be read - this is not an error
		return
	}

	// Parse the JSON data
	funcMap, err := parseWhitelistJSON(data)
	if err != nil {
		// Invalid JSON format - log but don't crash
		print("runtime: failed to parse whitelist config: ")
		println(err.Error())
		return
	}

	whitelistConfig.funcMap = funcMap
	whitelistConfig.loaded = true
}

// lookupFunctionWhitelist looks up the whitelist ID for a given function pointer.
// It returns the whitelist ID and true if found, or 0 and false if not found
// or if no config was loaded.
//
// This function is exported for testing and for use by the reflect package.
//
//go:linkname lookupFunctionWhitelist runtime.lookupFunctionWhitelist
func lookupFunctionWhitelist(fn unsafe.Pointer) (uint32, bool) {
	if !whitelistConfig.loaded || whitelistConfig.funcMap == nil {
		return 0, false
	}

	// Get the function info from the function pointer
	funcInfo := findfunc(uintptr(fn))
	if funcInfo._func == nil {
		// fn may be *runtime.funcval
		if fn != nil {
			entry := *(*uintptr)(fn)
			if entry != 0 {
				funcInfo = findfunc(entry)
			}
		}
	}
	if funcInfo._func == nil {
		return 0, false
	}

	// Get the function name
	funcName := funcname(funcInfo)
	if funcName == "" {
		return 0, false
	}

	// Look up in the map
	id, ok := whitelistConfig.funcMap[funcName]
	return id, ok
}

// readWhitelistConfigFile reads the entire contents of the specified file.
// Returns the file contents as a byte slice, or an error if the file cannot be read.
func readWhitelistConfigFile(filename string) ([]byte, error) {
	// Convert string to byte pointer
	filenameBytes := []byte(filename)
	filenameBytes = append(filenameBytes, 0) // null-terminate

	// Open the file
	fd := open(&filenameBytes[0], 0 /* O_RDONLY */, 0)
	if fd < 0 {
		return nil, errorString("file not found")
	}

	// Read file in chunks without stat
	// Most config files should be small, so we use a simple approach
	const maxSize = 1 << 23 // 8MB limit
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	for {
		n := read(fd, unsafe.Pointer(&tmp[0]), int32(len(tmp)))
		if n < 0 {
			closefd(fd)
			return nil, errorString("read failed")
		}
		if n == 0 {
			break
		}

		buf = append(buf, tmp[:n]...)
		if len(buf) > maxSize {
			closefd(fd)
			return nil, errorString("config file too large")
		}
	}

	closefd(fd)
	return buf, nil
}

// parseWhitelistJSON parses a simple JSON object mapping function names to
// whitelist IDs. Expected format:
//
//	{
//	  "function_whitelists": {
//	    "main.funcName": 1,
//	    "pkg.funcName": 2
//	  }
//	}
func parseWhitelistJSON(data []byte) (map[string]uint32, error) {
	result := make(map[string]uint32)

	// Simple state machine parser for our specific JSON structure
	i := 0

	// Skip whitespace
	skipWhitespace := func() {
		for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
			i++
		}
	}

	// Expect a specific byte
	expect := func(b byte) bool {
		skipWhitespace()
		if i >= len(data) || data[i] != b {
			return false
		}
		i++
		return true
	}

	// Parse a quoted string
	parseString := func() (string, bool) {
		skipWhitespace()
		if i >= len(data) || data[i] != '"' {
			return "", false
		}
		i++ // skip opening quote

		start := i
		for i < len(data) && data[i] != '"' {
			if data[i] == '\\' {
				i++ // skip escape character
			}
			i++
		}

		if i >= len(data) {
			return "", false
		}

		str := string(data[start:i])
		i++ // skip closing quote
		return str, true
	}

	// Parse a number
	parseNumber := func() (uint32, bool) {
		skipWhitespace()
		if i >= len(data) || (data[i] < '0' || data[i] > '9') {
			return 0, false
		}

		num := uint32(0)
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			num = num*10 + uint32(data[i]-'0')
			i++
		}
		return num, true
	}

	// Parse main object: { "function_whitelists": { ... } }
	if !expect('{') {
		return nil, errorString("expected '{'")
	}

	// Find "function_whitelists" key
	for {
		skipWhitespace()
		if i >= len(data) {
			return nil, errorString("unexpected end of JSON")
		}

		if data[i] == '}' {
			// Empty object or end of object
			break
		}

		key, ok := parseString()
		if !ok {
			return nil, errorString("expected string key")
		}

		if !expect(':') {
			return nil, errorString("expected ':'")
		}

		if key == "function_whitelists" {
			// Parse the nested object with function mappings
			if !expect('{') {
				return nil, errorString("expected '{' for function_whitelists")
			}

			// Parse function name -> ID mappings
			for {
				skipWhitespace()
				if i >= len(data) {
					return nil, errorString("unexpected end of JSON in function_whitelists")
				}

				if data[i] == '}' {
					i++
					break
				}

				funcName, ok := parseString()
				if !ok {
					return nil, errorString("expected function name string")
				}

				if !expect(':') {
					return nil, errorString("expected ':' after function name")
				}

				whitelistID, ok := parseNumber()
				if !ok {
					return nil, errorString("expected whitelist ID number")
				}

				result[funcName] = whitelistID

				skipWhitespace()
				if i < len(data) && data[i] == ',' {
					i++
				}
			}

			break
		} else {
			// Skip unknown key's value
			skipValue := func() bool {
				skipWhitespace()
				if i >= len(data) {
					return false
				}

				// Simple skip for string, number, object, or array
				switch data[i] {
				case '"':
					_, ok := parseString()
					return ok
				case '{', '[':
					depth := 1
					bracket := data[i]
					i++
					for i < len(data) && depth > 0 {
						if data[i] == bracket {
							depth++
						} else if (bracket == '{' && data[i] == '}') || (bracket == '[' && data[i] == ']') {
							depth--
						}
						i++
					}
					return depth == 0
				default:
					_, ok := parseNumber()
					return ok
				}
			}

			if !skipValue() {
				return nil, errorString("failed to skip unknown key value")
			}
		}

		skipWhitespace()
		if i < len(data) && data[i] == ',' {
			i++
		}
	}

	return result, nil
}
