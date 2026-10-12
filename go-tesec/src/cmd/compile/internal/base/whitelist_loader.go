// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !compiler_bootstrap

package base

import (
	"log"
	"os"
)

const defaultWhitelistConfigFilename = "whitelist_config.json"

func loadWhitelistConfig() {
	filename := os.Getenv("WHITELIST_CONFIG")
	if filename == "" {
		filename = defaultWhitelistConfigFilename
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	cfg, err := parseWhitelistConfig(data)
	if err != nil {
		log.Fatalf("invalid %s: %v", filename, err)
	}
	Flag.Cfg.Whitelist = cfg
}

func parseWhitelistConfig(data []byte) (*WhitelistConfig, error) {
	p := parser{data: data}
	cfg := &WhitelistConfig{FunctionIDs: make(map[string]uint32)}
	if err := p.expect('{'); err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		switch key {
		case "function_whitelists":
			if err := p.parseFunctionIDs(cfg.FunctionIDs); err != nil {
				return nil, err
			}
		case "location_whitelists":
			locs, err := p.parseLocations()
			if err != nil {
				return nil, err
			}
			cfg.Locations = locs
		case "signature", "signatures":
			sigs, err := p.parseSignatures()
			if err != nil {
				return nil, err
			}
			cfg.Signatures = append(cfg.Signatures, sigs...)
		default:
			if err := p.skipValue(); err != nil {
				return nil, err
			}
		}
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

type parser struct {
	data []byte
	i    int
}

type parseError string

func (e parseError) Error() string { return string(e) }

func (p *parser) eof() bool { return p.i >= len(p.data) }

func (p *parser) peek() byte { return p.data[p.i] }

func (p *parser) next() { p.i++ }

func (p *parser) skipWhitespace() {
	for !p.eof() {
		switch p.data[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) expect(b byte) error {
	p.skipWhitespace()
	if p.eof() || p.data[p.i] != b {
		return parseError("unexpected token")
	}
	p.i++
	return nil
}

func (p *parser) parseString() (string, error) {
	p.skipWhitespace()
	if p.eof() || p.data[p.i] != '"' {
		return "", parseError("expected string")
	}
	p.i++
	start := p.i
	for !p.eof() {
		c := p.data[p.i]
		if c == '\\' {
			p.i += 2
			continue
		}
		if c == '"' {
			break
		}
		p.i++
	}
	if p.eof() {
		return "", parseError("unterminated string")
	}
	s := string(p.data[start:p.i])
	p.i++
	return s, nil
}

func (p *parser) parseNumber() (uint32, error) {
	p.skipWhitespace()
	if p.eof() {
		return 0, parseError("expected number")
	}
	var n uint32
	digits := 0
	for !p.eof() {
		c := p.data[p.i]
		if c < '0' || c > '9' {
			break
		}
		digits++
		n = n*10 + uint32(c-'0')
		p.i++
	}
	if digits == 0 {
		return 0, parseError("expected number")
	}
	return n, nil
}

func (p *parser) parseFunctionIDs(dst map[string]uint32) error {
	if err := p.expect('{'); err != nil {
		return err
	}
	for {
		p.skipWhitespace()
		if p.eof() {
			return parseError("unexpected end of JSON in function_whitelists")
		}
		if p.peek() == '}' {
			p.next()
			return nil
		}
		name, err := p.parseString()
		if err != nil {
			return err
		}
		if err := p.expect(':'); err != nil {
			return err
		}
		id, err := p.parseNumber()
		if err != nil {
			return err
		}
		dst[name] = id
		p.skipWhitespace()
		if p.eof() {
			return parseError("unexpected end of JSON in function_whitelists")
		}
		if p.peek() == '}' {
			p.next()
			return nil
		}
		if err := p.expect(','); err != nil {
			return err
		}
	}
}

func (p *parser) parseLocations() ([]WhitelistLocation, error) {
	if err := p.expect('['); err != nil {
		return nil, err
	}
	var locs []WhitelistLocation
	for {
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON in location_whitelists")
		}
		if p.peek() == ']' {
			p.next()
			break
		}
		loc, err := p.parseLocation()
		if err != nil {
			return nil, err
		}
		locs = append(locs, loc)
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON in location_whitelists")
		}
		if p.peek() == ']' {
			p.next()
			break
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
	}
	return locs, nil
}

func (p *parser) parseLocation() (WhitelistLocation, error) {
	if err := p.expect('{'); err != nil {
		return WhitelistLocation{}, err
	}
	var loc WhitelistLocation
	for {
		p.skipWhitespace()
		if p.eof() {
			return WhitelistLocation{}, parseError("unexpected end of JSON in location")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		key, err := p.parseString()
		if err != nil {
			return WhitelistLocation{}, err
		}
		if err := p.expect(':'); err != nil {
			return WhitelistLocation{}, err
		}
		switch key {
		case "file":
			s, err := p.parseString()
			if err != nil {
				return WhitelistLocation{}, err
			}
			loc.File = s
		case "line":
			n, err := p.parseNumber()
			if err != nil {
				return WhitelistLocation{}, err
			}
			loc.Line = n
		case "col":
			n, err := p.parseNumber()
			if err != nil {
				return WhitelistLocation{}, err
			}
			loc.Col = n
		case "id":
			n, err := p.parseNumber()
			if err != nil {
				return WhitelistLocation{}, err
			}
			loc.ID = n
		default:
			if err := p.skipValue(); err != nil {
				return WhitelistLocation{}, err
			}
		}
		p.skipWhitespace()
		if p.eof() {
			return WhitelistLocation{}, parseError("unexpected end of JSON in location")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		if err := p.expect(','); err != nil {
			return WhitelistLocation{}, err
		}
	}
	return loc, nil
}

func (p *parser) parseSignature() (WhitelistSignature, error) {
	if err := p.expect('{'); err != nil {
		return WhitelistSignature{}, err
	}
	var sig WhitelistSignature
	for {
		p.skipWhitespace()
		if p.eof() {
			return WhitelistSignature{}, parseError("unexpected end of JSON in signature")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		key, err := p.parseString()
		if err != nil {
			return WhitelistSignature{}, err
		}
		if err := p.expect(':'); err != nil {
			return WhitelistSignature{}, err
		}
		switch key {
		case "params":
			vals, err := p.parseStringArray()
			if err != nil {
				return WhitelistSignature{}, err
			}
			sig.Params = vals
		case "results":
			vals, err := p.parseStringArray()
			if err != nil {
				return WhitelistSignature{}, err
			}
			sig.Results = vals
		default:
			if err := p.skipValue(); err != nil {
				return WhitelistSignature{}, err
			}
		}
		p.skipWhitespace()
		if p.eof() {
			return WhitelistSignature{}, parseError("unexpected end of JSON in signature")
		}
		if p.peek() == '}' {
			p.next()
			break
		}
		if err := p.expect(','); err != nil {
			return WhitelistSignature{}, err
		}
	}
	return sig, nil
}

func (p *parser) parseSignatures() ([]WhitelistSignature, error) {
	p.skipWhitespace()
	if p.eof() {
		return nil, parseError("unexpected end of JSON in signature")
	}
	switch p.peek() {
	case '{':
		sig, err := p.parseSignature()
		if err != nil {
			return nil, err
		}
		return []WhitelistSignature{sig}, nil
	case '[':
		if err := p.expect('['); err != nil {
			return nil, err
		}
		var sigs []WhitelistSignature
		for {
			p.skipWhitespace()
			if p.eof() {
				return nil, parseError("unexpected end of JSON in signature array")
			}
			if p.peek() == ']' {
				p.next()
				break
			}
			sig, err := p.parseSignature()
			if err != nil {
				return nil, err
			}
			sigs = append(sigs, sig)
			p.skipWhitespace()
			if p.eof() {
				return nil, parseError("unexpected end of JSON in signature array")
			}
			if p.peek() == ']' {
				p.next()
				break
			}
			if err := p.expect(','); err != nil {
				return nil, err
			}
		}
		return sigs, nil
	default:
		return nil, parseError("expected signature object or array")
	}
}

func (p *parser) parseStringArray() ([]string, error) {
	if err := p.expect('['); err != nil {
		return nil, err
	}
	var out []string
	for {
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON in array")
		}
		if p.peek() == ']' {
			p.next()
			break
		}
		val, err := p.parseString()
		if err != nil {
			return nil, err
		}
		out = append(out, val)
		p.skipWhitespace()
		if p.eof() {
			return nil, parseError("unexpected end of JSON in array")
		}
		if p.peek() == ']' {
			p.next()
			break
		}
		if err := p.expect(','); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (p *parser) skipValue() error {
	p.skipWhitespace()
	if p.eof() {
		return parseError("unexpected end of JSON")
	}
	switch p.peek() {
	case '"':
		_, err := p.parseString()
		return err
	case '{':
		return p.skipDelimited('{', '}')
	case '[':
		return p.skipDelimited('[', ']')
	default:
		start := p.i
		for !p.eof() {
			c := p.peek()
			if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				p.next()
				continue
			}
			break
		}
		if start == p.i {
			return parseError("unable to skip value")
		}
		return nil
	}
}

func (p *parser) skipDelimited(open, close byte) error {
	p.next()
	depth := 1
	for !p.eof() && depth > 0 {
		switch p.peek() {
		case open:
			depth++
		case close:
			depth--
		case '"':
			if _, err := p.parseString(); err != nil {
				return err
			}
			continue
		}
		p.next()
	}
	if depth != 0 {
		return parseError("unterminated value")
	}
	return nil
}
