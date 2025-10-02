package main

import (
	"os"
	"fmt"
	
	"github.com/distix-pj/PoC1/cmd/poc1/command"
)

func main() {
	err := command.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
