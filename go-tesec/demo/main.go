package main

import "fmt"

// Map of functions
var actions = map[string]func(int) int{
	"double": func(x int) int { return x * 2 },
	"square": func(x int) int { return x * x },
}

// Function variable
var fn func(int) int

// Returns a function
func getAdder(n int) func(int) int {
	return func(x int) int { return x + n }
}

// Takes a function parameter
func apply(f func(int) int, x int) int {
	return f(x)
}

func main() {
	// 1. Map of functions call
	fmt.Println("=== map of functions ===")
	r1 := actions["double"](5)
	fmt.Println("double(5) =", r1)
	r2 := actions["square"](4)
	fmt.Println("square(4) =", r2)

	// 2. Function variable call
	fmt.Println("\n=== function variable ===")
	fn = actions["double"]
	r3 := fn(10)
	fmt.Println("fn(10) =", r3)

	// 3. Closure variable call
	fmt.Println("\n=== closure variable ===")
	adder := getAdder(3)
	r4 := adder(7)
	fmt.Println("adder(7) =", r4)

	// 4. Function parameter call
	fmt.Println("\n=== function parameter ===")
	r5 := apply(actions["square"], 6)
	fmt.Println("apply(square, 6) =", r5)

	// 5. Immediately invoked closure
	fmt.Println("\n=== immediate closure ===")
	r6 := func(x int) int { return x * x * x }(3)
	fmt.Println("cube(3) =", r6)

	// 6. Multiple calls to same target (dedup test)
	fmt.Println("\n=== dedup test ===")
	for i := 0; i < 3; i++ {
		actions["double"](i)
	}

	fmt.Println("\nDone!")
}
