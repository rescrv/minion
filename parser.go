package minion

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode"
)

type Minionfile struct {
	Processes []Process
	Sources   []Source
}

func (mf *Minionfile) GetSource(name string) Source {
	for _, src := range mf.Sources {
		if src.Name() == name {
			return src
		}
	}
	return nil
}

func (mf *Minionfile) GetProcess(name string) Process {
	for _, proc := range mf.Processes {
		if proc.Name() == name {
			return proc
		}
	}
	return nil
}

type Process interface {
	Name() string
	EnvVar() string
	Dependencies() []Dependency
	Artifacts() []Artifact
	Processor(bd *Build) Processor
}

type Source interface {
	Name() string
	EnvVar() string
	Update(md *MinionDaemon) (HeadPtr, error)
}

type HeadPtr struct {
	RefSpec string
	RefName string
}

func HeadPtrsSame(a HeadPtr, b HeadPtr) bool {
	return a.RefSpec == b.RefSpec && a.RefName == b.RefName
}

type Dependency interface {
	Display() string
	Type() string
	EnvVar() string
	Soft() bool
	Full() bool
}

type Artifact struct {
	Process string
	Name    string
}

func (a Artifact) Display() string {
	return strings.Join([]string{a.Process, "=>", a.Name}, "")
}

func (a Artifact) EnvVar() string {
	return IdentifierToEnvVar(a.Display(), "artifact")
}

type ArtifactPtr struct {
	Blob BlobID
	Path string
}

type FetchSource struct {
	name string
	url  string
	hash string
}

func (fs FetchSource) Name() string {
	return fs.name
}

func (fs FetchSource) EnvVar() string {
	return SourceEnvVar(fs.Name())
}

func (fs FetchSource) Update(md *MinionDaemon) (HeadPtr, error) {
	return md.updateFetchSource(fs)
}

func NewFetchSource(name string, url string, hash string) Source {
	return FetchSource{name, url, hash}
}

type GitSource struct {
	name   string
	url    string
	branch string
}

func (gs GitSource) Name() string {
	return gs.name
}

func (gs GitSource) EnvVar() string {
	return SourceEnvVar(gs.Name())
}

func (gs GitSource) Update(md *MinionDaemon) (HeadPtr, error) {
	return md.updateGitSource(gs)
}

func NewGitSource(name string, url string, branch string) Source {
	return GitSource{name, url, branch}
}

type DockerfileProcess struct {
	name       string
	dockerfile string
	deps       []Dependency
	arts       []string
}

func (dp DockerfileProcess) Name() string {
	return dp.name
}

func (dp DockerfileProcess) EnvVar() string {
	return IdentifierToEnvVar(dp.Name(), "process")
}

func (dp DockerfileProcess) Dependencies() []Dependency {
	return dp.deps
}

func (dp DockerfileProcess) Artifacts() []Artifact {
	arts := make([]Artifact, 0, len(dp.arts))
	for _, a := range dp.arts {
		arts = append(arts, Artifact{dp.name, a})
	}
	return arts
}

func (dp DockerfileProcess) Processor(bd *Build) Processor {
	return bd.md.dockerfileProcessor(dp, bd)
}

func NewDockerfileProcess(name string, dockerfile string, deps []Dependency, arts []string) Process {
	return DockerfileProcess{name, dockerfile, deps, arts}
}

type SourceDependency struct {
	name string
	soft bool
	full bool
}

func (sd SourceDependency) Display() string {
	return sd.name
}

func (sd SourceDependency) Type() string {
	return "source"
}

func (sd SourceDependency) EnvVar() string {
	return IdentifierToEnvVar(sd.Display(), "source")
}

func (sd SourceDependency) Soft() bool {
	return sd.soft
}

func (sd SourceDependency) Full() bool {
	return sd.full
}

func NewSourceDependency(name string, soft bool, full bool) Dependency {
	return SourceDependency{name, soft, full}
}

type ArtifactDependency struct {
	Artifact
	soft bool
	full bool
}

func (ad ArtifactDependency) Display() string {
	return strings.Join([]string{ad.Process, "=>", ad.Name}, "")
}

func (ad ArtifactDependency) Type() string {
	return "artifact"
}

func (ad ArtifactDependency) EnvVar() string {
	return IdentifierToEnvVar(ad.Display(), "artifact")
}

func (ad ArtifactDependency) Soft() bool {
	return ad.soft
}

func (ad ArtifactDependency) Full() bool {
	return ad.full
}

func NewArtifactDependency(process string, name string, soft bool, full bool) Dependency {
	return ArtifactDependency{Artifact{process, name}, soft, full}
}

func NormalizeString(s string) string {
	f := func(c rune) rune {
		if c >= 128 {
			return '_'
		} else if !unicode.IsDigit(c) && !unicode.IsLetter(c) {
			return '_'
		} else {
			return c
		}
	}
	s = strings.Map(f, s)
	ss := strings.Split(s, "_")
	ns := make([]string, 0, len(ss))
	for _, p := range ss {
		if len(p) > 0 {
			ns = append(ns, p)
		}
	}
	return strings.Join(ns, "_")
}

func IdentifierToEnvVar(identifier string, prefix string) string {
	s := strings.Join([]string{"MINION_", prefix, "_", identifier}, "")
	s = strings.ToUpper(s)
	return NormalizeString(s)
}

func SourceEnvVar(identifier string) string {
	return IdentifierToEnvVar(identifier, "source")
}

var mtx = sync.Mutex{}

func ParseMinionfile(path string) (mf Minionfile, err error) {
	mtx.Lock()
	parserErrorVerbose = true
	mtx.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	lexer := NewLexer(f)
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			err = fmt.Errorf("%s near line %d", r.(error), lexer.lineno)
		}
	}()
	lex := &parserLex{lexer: lexer}
	parserParse(lex)
	mf = lex.mf
	envvars := map[string]int{}
	for _, s := range mf.Sources {
		if strings.ContainsRune(s.Name(), '/') {
			err = fmt.Errorf("source %s should contains a directory separator", s.Name(), s.Name(), NormalizeString(s.Name()))
			return
		}
		if _, ok := envvars[s.EnvVar()]; ok {
			err = fmt.Errorf("environment variable %s ambiguously overloaded", s.EnvVar())
			return
		}
		envvars[s.EnvVar()] = 1
	}
	for _, p := range mf.Processes {
		if _, ok := envvars[p.EnvVar()]; ok {
			err = fmt.Errorf("environment variable %s ambiguously overloaded", p.EnvVar())
			return
		}
		envvars[p.EnvVar()] = 1
		for _, d := range p.Dependencies() {
			if _, ok := envvars[d.EnvVar()]; !ok {
				err = fmt.Errorf("process %s depends on unknown %s %s", p.Name(), d.Type(), d.Display())
				return
			}
		}
		for _, a := range p.Artifacts() {
			if _, ok := envvars[a.EnvVar()]; ok {
				err = fmt.Errorf("environment variable %s ambiguously overloaded", p.EnvVar())
				return
			}
			envvars[a.EnvVar()] = 1
		}
	}
	return lex.mf, nil
}
