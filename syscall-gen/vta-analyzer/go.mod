module vta-analyzer

go 1.24.7

toolchain go1.24.9

require (
	golang.org/x/tools v0.40.0
	linkname-analyzer v0.0.0-00010101000000-000000000000
)

require github.com/bits-and-blooms/bitset v1.24.4

require (
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.7 // direct
	github.com/fatih/color v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

require (
	asm-analyzer v0.0.0-00010101000000-000000000000
	golang.org/x/mod v0.31.0
	golang.org/x/sync v0.19.0 // indirect
)

replace linkname-analyzer => ../linkname-analyzer

replace asm-analyzer => ../asm-analyzer
