package base

import "testing"

func TestWhitelistConfigParse(t *testing.T) {
	data := []byte(`{
		"function_whitelists": {
			"example.com/pkg.Func": 42
		},
		"signatures": [
			{
				"params": ["int", "string"],
				"results": ["error"]
			}
		]
	}`)

	cfg, err := parseWhitelistConfig(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if got := cfg.FunctionIDs["example.com/pkg.Func"]; got != 42 {
		t.Fatalf("unexpected whitelist id %d", got)
	}
	if len(cfg.Signatures) != 1 {
		t.Fatalf("expected signature block")
	}
	if len(cfg.Signatures[0].Params) != 2 || cfg.Signatures[0].Params[0] != "int" || cfg.Signatures[0].Params[1] != "string" {
		t.Fatalf("params mismatch: %#v", cfg.Signatures[0].Params)
	}
	if len(cfg.Signatures[0].Results) != 1 || cfg.Signatures[0].Results[0] != "error" {
		t.Fatalf("results mismatch: %#v", cfg.Signatures[0].Results)
	}
}

func TestWhitelistConfigSkipsUnknown(t *testing.T) {
	data := []byte(`{
		"version": "2.0",
		"function_whitelists": {},
		"signatures": [{}],
		"unknown": [1, 2, 3]
	}`)

	if _, err := parseWhitelistConfig(data); err != nil {
		t.Fatalf("Parse should ignore unknown keys: %v", err)
	}
}
