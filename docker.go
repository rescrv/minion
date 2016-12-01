package minion

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"time"
)

type DockerfileProcessor struct {
	DockerfileProcess
	bd *Build
}

func (md *MinionDaemon) dockerfileProcessor(dp DockerfileProcess, bd *Build) Processor {
	return DockerfileProcessor{dp, bd}
}

func (dp DockerfileProcessor) BuildIt(sources map[string]HeadPtr, artifacts ArtifactMap) (pr ProcessReport) {
	pr = ProcessReport{Status: ERROR,
		Cached:    false,
		Released:  false,
		StatusMsg: "unknown error",
		Log:       "",
		Inputs:    BlobID(""),
		Artifacts: make(ArtifactMap)}
	// check for a cached release
	inputs := dp.inputs(sources, artifacts, "-")
	var err error
	pr.Inputs, err = dp.bd.md.blobs.Cat([]byte(inputs))
	if err != nil {
		pr.StatusMsg = fmt.Sprintf("could not record inputs: %s", err)
		return
	}
	if oid, cached := dp.bd.md.isCached(pr.Inputs); cached {
		new_pr, err := dp.bd.md.readProcessReport(oid)
		if err != nil {
			pr.StatusMsg = fmt.Sprintf("could not read cached process report: %s", err)
			return
		}
		new_pr.Cached = true
		return new_pr
	}
	// build the docker image
	image, err := dp.buildImage()
	if err != nil {
		pr.StatusMsg = fmt.Sprintf("could not build docker image: %s", err)
		return
	}
	// check for a cached version of this image
	inputs = dp.inputs(sources, artifacts, image)
	pr.Inputs, err = dp.bd.md.blobs.Cat([]byte(inputs))
	if err != nil {
		pr.StatusMsg = fmt.Sprintf("could not record inputs: %s", err)
		return
	}
	if oid, cached := dp.bd.md.isCached(pr.Inputs); cached {
		new_pr, err := dp.bd.md.readProcessReport(oid)
		if err != nil {
			pr.StatusMsg = fmt.Sprintf("could not read cached process report: %s", err)
			return
		}
		new_pr.Cached = true
		if new_pr.Status == SUCCESS || !dp.bd.retry {
			return new_pr
		}
	}
	tmpdir, err := ioutil.TempDir(dp.bd.md.TMP(), "minion-docker-")
	if err != nil {
		pr.StatusMsg = fmt.Sprintf("could not create temporary directory: %s", err)
		return
	}
	// now execute
	args := make([]string, 0)
	args = append(args, "run", "--privileged")
	for _, dep := range dp.deps {
		if s, ok := dep.(SourceDependency); ok {
			ptr, ok := sources[s.name]
			if !ok {
				panic(fmt.Errorf("unknown source %s", s.name))
			}
			if len(ptr.RefSpec) == 40 {
				cmd := exec.Command("git", "clone", "--no-local", "--no-hardlinks",
					path.Join(dp.bd.md.GITREPOS(), s.name),
					path.Join(tmpdir, s.name))
				out, err := cmd.CombinedOutput()
				if err != nil {
					pr.StatusMsg = fmt.Sprintf("could not setup dependencies: %s\n%s", err, out)
					return
				}
				cmd = exec.Command("git", "checkout", ptr.RefSpec)
				cmd.Dir = path.Join(tmpdir, s.name)
				out, err = cmd.CombinedOutput()
				if err != nil {
					pr.StatusMsg = fmt.Sprintf("could not setup dependencies: %s\n%s", err, out)
					return
				}
				args = append(args, "-e", fmt.Sprintf("%s=%s", s.EnvVar(), path.Join("/deps", s.name)))
			} else if len(ptr.RefSpec) == 64 {
				p := path.Join(tmpdir, s.name)
				err = dp.bd.md.blobs.CopyTo(BlobID(ptr.RefSpec), p)
				if err != nil {
					pr.StatusMsg = fmt.Sprintf("could not setup dependencies: %s", err)
					return
				}
				args = append(args, "-e", fmt.Sprintf("%s=%s", s.EnvVar(), path.Join("/deps", ptr.RefName)))
			} else {
				panic("Unknown head pointer format")
			}
		} else if a, ok := dep.(ArtifactDependency); ok {
			if _, ok = artifacts[a.Artifact]; !ok {
				panic(fmt.Errorf("unknown artifact %s", a.Display()))
			}
			intermediate := ""
			if a.Full() {
				intermediate = a.Artifact.Process
			}
			dirn := path.Join(tmpdir, intermediate)
			err = os.MkdirAll(dirn, 0700)
			if err != nil {
				pr.StatusMsg = fmt.Sprintf("could not create directory: %s", err)
				return
			}
			aptr := artifacts[a.Artifact]
			err = dp.bd.md.blobs.CopyTo(aptr.Blob, path.Join(dirn, aptr.Path))
			if err != nil {
				pr.StatusMsg = fmt.Sprintf("could not setup dependencies: %s", err)
				return
			}
			args = append(args, "-e", fmt.Sprintf("%s=%s", a.EnvVar(), path.Join("/deps", intermediate, aptr.Path)))
		} else {
			panic(fmt.Errorf("unhandled dependency type"))
		}
	}
	tmpdir, err = filepath.Abs(tmpdir)
	if err != nil {
		pr.StatusMsg = fmt.Sprintf("could not traverse path: %s", err)
		return
	}
	defer os.RemoveAll(tmpdir)
	name := fmt.Sprintf("%s-%d", pr.Inputs, time.Now().UnixNano())
	args = append(args, "--name", name)
	args = append(args, "-v", tmpdir+":/deps")
	args = append(args, image)
	cmd := exec.Command("docker", args...)
	cmd.Dir = dp.bd.md.BUILD()
	bout, err := cmd.CombinedOutput()
	pr.Log = string(bout)
	if err != nil {
		pr.Status = FAILED
		pr.StatusMsg = fmt.Sprintf("process failed: %s", err)
		return
	}
	rmcmd := exec.Command("docker", "rm", name)
	defer rmcmd.CombinedOutput()
	new_artifacts := make(map[string]ArtifactPtr)
	re := regexp.MustCompile("(MINION_ARTIFACT_.*?)=(.*?)\n")
	for _, match := range re.FindAllStringSubmatch(pr.Log, -1) {
		if len(match) != 3 {
			continue
		}
		cmd = exec.Command("docker", "cp", name+":"+match[2], tmpdir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			pr.StatusMsg = fmt.Sprintf("could not collect artifacts: %s\n%s", err, out)
			return
		}
		bname := path.Base(match[2])
		bid, err := dp.bd.md.blobs.Add(path.Join(tmpdir, bname))
		if err != nil {
			pr.StatusMsg = fmt.Sprintf("could not collect artifacts: %s", err)
			return
		}
		new_artifacts[match[1]] = ArtifactPtr{bid, bname}
	}
	for _, name := range dp.arts {
		art := Artifact{dp.name, name}
		if ptr, ok := new_artifacts[art.EnvVar()]; ok {
			pr.Artifacts[art] = ptr
		} else {
			pr.StatusMsg = fmt.Sprintf("failed to produce artifact %s", name)
			return
		}
	}
	pr.Status = SUCCESS
	pr.StatusMsg = ""
	return
}

func (dp DockerfileProcessor) inputs(sources map[string]HeadPtr, artifacts ArtifactMap, image string) string {
	inputs := fmt.Sprintf("Dockerfile\nProcess: %s\nImage: %s\n", dp.Name(), image)
	for _, dep := range dp.deps {
		if dep.Soft() {
			continue
		}
		if s, ok := dep.(SourceDependency); ok {
			if _, ok = sources[s.name]; !ok {
				panic(fmt.Errorf("unknown source %s", s.name))
			}
			inputs += fmt.Sprintf("Dependency %s: %s\n", s.name, sources[s.name].RefSpec)
		} else if a, ok := dep.(ArtifactDependency); ok {
			if _, ok = artifacts[a.Artifact]; !ok {
				panic(fmt.Errorf("unknown artifact %s", a.Display()))
			}
			inputs += fmt.Sprintf("Dependency %s: %s\n", a.Name, artifacts[a.Artifact].Blob)
		} else {
			panic(fmt.Errorf("unhandled dependency type"))
		}
	}
	for _, art := range dp.arts {
		inputs += fmt.Sprintf("Artifact %s\n", art)
	}
	return inputs
}

func (dp DockerfileProcessor) buildImage() (string, error) {
	cmd := exec.Command("docker", "build", dp.DockerfileProcess.dockerfile)
	cmd.Dir = dp.bd.md.BUILD()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("Successfully built ([0-9A-Fa-f]+)")
	match := re.FindStringSubmatch(string(out))
	if len(match) < 2 || match[1] == "" {
		return "", fmt.Errorf("docker output did not contain image ID")
	}
	return match[1], nil
}
