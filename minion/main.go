package main

import (
	"flag"
	"fmt"
	"git.rescrv.net/minion"
	"os"
	"time"
)

var workdir = flag.String("d", ".", "the working directory for the daemon")

func main_new_target(mrpc *minion.MinionRPCClient, name string) {
	err := mrpc.NewTarget(name)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
}

func main_del_target(mrpc *minion.MinionRPCClient, name string) {
	err := mrpc.DelTarget(name)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
}

func main_list_targets(mrpc *minion.MinionRPCClient) {
	targets, err := mrpc.ListTargets()
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
	for _, t := range targets {
		fmt.Printf("%s\n", t)
	}
}

func main_sync_sources(mrpc *minion.MinionRPCClient, srcs []string) {
	result, err := mrpc.SyncSources([]string{})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
	for _, r := range result.Removed {
		fmt.Printf("removed %s\n", r)
	}
	for _, a := range result.Added {
		fmt.Printf("added %s\n", a)
	}
	for _, c := range result.Changed {
		fmt.Printf("changed %s\n", c)
	}
}

func main_set_refspec(mrpc *minion.MinionRPCClient, target string, source string, refspec string) {
	err := mrpc.TargetSetRefSpec(target, source, refspec)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(2)
	}
}

func main_build(mrpc *minion.MinionRPCClient, target string, name string) {
	rep, err := mrpc.Build(target, name, true, []string{})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	}
	fmt.Printf(rep.ReportLong())
}

func main() {
	flag.Parse()
	mrpc, err := minion.NewMinionRPCClient(*workdir)
	if err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
	args := flag.Args()
	if len(args) < 1 {
		fmt.Printf("error: must specify a command\n")
		os.Exit(1)
	}
	switch args[0] {
	case "new-target":
		if len(args) != 2 {
			fmt.Printf("error: expected 2 arguments, got %d\n", len(args))
			os.Exit(1)
		}
		main_new_target(mrpc, args[1])
	case "del-target":
		if len(args) != 2 {
			fmt.Printf("error: expected 2 arguments, got %d\n", len(args))
			os.Exit(1)
		}
		main_del_target(mrpc, args[1])
	case "list-targets":
		if len(args) != 1 {
			fmt.Printf("error: expected 1 argument, got %d\n", len(args))
			os.Exit(1)
		}
		main_list_targets(mrpc)
	case "sync-sources":
		main_sync_sources(mrpc, args[1:])
	case "set-refspec":
		if len(args) != 4 {
			fmt.Printf("error: expected 4 arguments, got %d\n", len(args))
			os.Exit(1)
		}
		main_set_refspec(mrpc, args[1], args[2], args[3])
	case "build":
		switch len(args) {
		case 2:
			name := time.Now().Format("2006-01-02T15:04:05Z")
			main_build(mrpc, args[1], name)
		case 3:
			main_build(mrpc, args[1], args[2])
		default:
			fmt.Printf("error: expected 2 or 3 arguments, got %d\n", len(args))
			os.Exit(1)
		}
	default:
		fmt.Printf("error: unknown command %s\n", args[0])
		os.Exit(1)
	}
}
