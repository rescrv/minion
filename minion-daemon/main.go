package main

import (
	"flag"
	"fmt"
	"git.rescrv.net/minion"
)

var workdir = flag.String("d", ".", "the working directory for the daemon")

func main() {
	flag.Parse()
	mrpc, err := minion.NewMinionRPCServer(*workdir)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	}
	mrpc.Run()
}
