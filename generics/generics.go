package main

import (
	"fmt"
)

type Foo[T any] interface {
	~int | ~int64
	Get(key T) T
}

type x Foo[int]

type xxx[T x] interface {
	xxx(T T) string
}

func X[T Foo[T]](input T) string {
	x := input.Get(input)

	fmt.Println(x)
	return ""
}

type z int

func (z) Get(z) z {
	return 1
}

func main() {
	var input z
	x := X(input)
	fmt.Println(x)
}
