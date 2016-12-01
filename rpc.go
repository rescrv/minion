package minion

import (
	"fmt"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"path"
	"syscall"
)

type InnerMinionRPCServer struct {
	md *MinionDaemon
}

type MinionRPCServer struct {
	mrpc *InnerMinionRPCServer
}

type MinionRPCClient struct {
	client *rpc.Client
}

func NewMinionRPCServer(p string) (*MinionRPCServer, error) {
	md, err := NewMinionDaemon(p)
	if err != nil {
		return nil, err
	}
	p = path.Join(p, "minion.sock")
	os.Remove(p)
	listener, err := net.Listen("unix", p)
	if err != nil {
		return nil, fmt.Errorf("unable to listen at %s: %s", p, err)
	}
	mrpc := &InnerMinionRPCServer{md}
	rpc.Register(mrpc)
	go rpc.Accept(listener)
	return &MinionRPCServer{mrpc}, nil
}

func NewMinionRPCClient(workdir string) (*MinionRPCClient, error) {
	client, err := rpc.Dial("unix", path.Join(workdir, "minion.sock"))
	return &MinionRPCClient{client}, err
}

func (mrpc *MinionRPCServer) Run() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGKILL, syscall.SIGHUP)
	<-signals
}

func (mrpc *InnerMinionRPCServer) NewTarget(name string, success *bool) error {
	err := mrpc.md.NewTarget(name)
	*success = err == nil
	return err
}

func (mrpc *MinionRPCClient) NewTarget(name string) error {
	var success bool = false
	err := mrpc.client.Call("InnerMinionRPCServer.NewTarget", name, &success)
	if success {
		return nil
	} else {
		return fmt.Errorf("could not make target: %s", err)
	}
}

func (mrpc *InnerMinionRPCServer) DelTarget(name string, success *bool) error {
	err := mrpc.md.DelTarget(name)
	*success = err == nil
	return err
}

func (mrpc *MinionRPCClient) DelTarget(name string) error {
	var success bool = false
	err := mrpc.client.Call("InnerMinionRPCServer.DelTarget", name, &success)
	if success {
		return nil
	} else {
		return fmt.Errorf("could not remove target: %s", err)
	}
}

func (mrpc *InnerMinionRPCServer) ListTargets(x int, targets *[]string) error {
	var err error
	*targets, err = mrpc.md.ListTargets()
	return err
}

func (mrpc *MinionRPCClient) ListTargets() ([]string, error) {
	var targets []string
	err := mrpc.client.Call("InnerMinionRPCServer.ListTargets", 8, &targets)
	if err == nil {
		return targets, nil
	} else {
		return nil, fmt.Errorf("could not list targets: %s", err)
	}
}

type SyncSourcesResult struct {
	Removed []string
	Changed []string
	Added   []string
}

func (mrpc *InnerMinionRPCServer) SyncSources(sources []string, result *SyncSourcesResult) error {
	var err error
	result.Removed, result.Changed, result.Added, err = mrpc.md.SyncSources(sources)
	return err
}

func (mrpc *MinionRPCClient) SyncSources(sources []string) (SyncSourcesResult, error) {
	var result SyncSourcesResult
	err := mrpc.client.Call("InnerMinionRPCServer.SyncSources", sources, &result)
	if err == nil {
		return result, nil
	} else {
		return result, fmt.Errorf("could not sync sources: %s", err)
	}
}

type TargetSetRefSpecRequest struct {
	Target  string
	Source  string
	RefSpec string
}

func (mrpc *InnerMinionRPCServer) TargetSetRefSpec(req TargetSetRefSpecRequest, success *bool) error {
	err := mrpc.md.TargetSetRefSpec(req.Target, req.Source, req.RefSpec)
	*success = err == nil
	return err
}

func (mrpc *MinionRPCClient) TargetSetRefSpec(target string, source string, refspec string) error {
	req := TargetSetRefSpecRequest{target, source, refspec}
	var success bool
	err := mrpc.client.Call("InnerMinionRPCServer.TargetSetRefSpec", req, &success)
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("could not set target refspec: %s", err)
	}
}

type GetBuildRequest struct {
	Target    string
	BuildName string
}

func (mrpc *InnerMinionRPCServer) GetBuild(req GetBuildRequest, resp *BuildReport) error {
	var rep *BuildReport = nil
	var err error
	rep, err = mrpc.md.GetBuild(req.Target, req.BuildName)
	if err == nil {
		return fmt.Errorf("build failed: %s", err)
	} else {
		*resp = *rep
		return nil
	}
}

func (mrpc *MinionRPCClient) GetBuild(target string, build_name string) (*BuildReport, error) {
	req := GetBuildRequest{target, build_name}
	var report BuildReport
	err := mrpc.client.Call("InnerMinionRPCServer.GetBuild", req, &report)
	if err == nil {
		return &report, nil
	} else {
		return nil, fmt.Errorf("could not build: %s", err)
	}
}

type GetArtifactsRequest struct {
	Target    string
	BuildName string
	DirName   string
}

func (mrpc *InnerMinionRPCServer) GetArtifacts(req GetArtifactsRequest, success *bool) error {
	var err error
	*success = false
	if req.BuildName == "latest" {
		b, err := mrpc.md.IdentifyLatestBuild(req.Target)
		if err != nil {
			return fmt.Errorf("could not identify latest build: %s", err)
		} else if b.Target != req.Target {
			return fmt.Errorf("no builds for %s found", req.Target)
		}
		req.BuildName = b.Name
	}
	err = mrpc.md.GetArtifacts(req.Target, req.BuildName, req.DirName)
	if err != nil {
		return fmt.Errorf("failed to get artifacts: %s", err)
	} else {
		*success = true
		return nil
	}
}

func (mrpc *MinionRPCClient) GetArtifacts(target string, build_name string, dir string) error {
	req := GetArtifactsRequest{target, build_name, dir}
	var success bool = false
	err := mrpc.client.Call("InnerMinionRPCServer.GetArtifacts", req, &success)
	if success {
		return nil
	} else {
		return fmt.Errorf("could not get artifacts: %s", err)
	}
}

type BuildRequest struct {
	Target        string
	BuildName     string
	RetryFailures bool
	Processes     []string
}

func (mrpc *InnerMinionRPCServer) Build(req BuildRequest, report *BuildReport) error {
	var rep *BuildReport = nil
	var err error
	rep, err = mrpc.md.Build(req.Target, req.BuildName, req.RetryFailures, req.Processes)
	if rep == nil && err == nil {
		return fmt.Errorf("build failed to produce a report or an error")
	} else if rep == nil {
		return fmt.Errorf("build failed: %s", err)
	} else {
		*report = *rep
		return nil
	}
}

func (mrpc *MinionRPCClient) Build(target string, build_name string, retry_failures bool, processes []string) (*BuildReport, error) {
	req := BuildRequest{target, build_name, retry_failures, processes}
	var report BuildReport
	err := mrpc.client.Call("InnerMinionRPCServer.Build", req, &report)
	if err == nil {
		return &report, nil
	} else {
		return nil, fmt.Errorf("could not build: %s", err)
	}
}
