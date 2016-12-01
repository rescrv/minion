package minion

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type MinionDaemon struct {
	workdir   string
	blobs     *BlobStore
	lock      *os.File
	headsMtx  sync.Mutex
	buildsMtx sync.Mutex
	builds    map[BuildInfo]*Build
	procCache *ProcessCache
}

func NewMinionDaemon(workdir string) (*MinionDaemon, error) {
	log.Printf("starting minion-daemon in %s\n", workdir)
	md := &MinionDaemon{workdir, nil, nil, sync.Mutex{}, sync.Mutex{}, make(map[BuildInfo]*Build), nil}
	err := os.MkdirAll(md.workdir, 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create %s: %s", workdir, err)
	}
	err = md.lockWorkdir()
	if err != nil {
		return nil, fmt.Errorf("could not lock %s: %s", workdir, err)
	}
	err = os.MkdirAll(md.BLOBDIR(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create blob dir: %s", err)
	}
	err = os.MkdirAll(md.BUILDS(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create builds dir: %s", err)
	}
	err = os.MkdirAll(md.PROCESSES(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create processes dir: %s", err)
	}
	err = os.MkdirAll(md.GITREPOS(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create git repos dir: %s", err)
	}
	err = os.MkdirAll(md.GITCACHE(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create git cache dir: %s", err)
	}
	err = os.MkdirAll(md.TMP(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create temp dir: %s", err)
	}
	err = os.MkdirAll(md.TARGETS(), 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create targets dir: %s", err)
	}
	err = md.ensureGitCacheExists()
	if err != nil {
		return nil, fmt.Errorf("could not create git cache: %s", err)
	}
	md.blobs = NewBlobStore(md.BLOBDIR())
	md.procCache = NewProcessCache(md.PROCESSES())
	return md, nil
}

func (md *MinionDaemon) LOCK() string {
	return path.Join(md.workdir, "LOCK")
}

func (md *MinionDaemon) BLOBDIR() string {
	return path.Join(md.workdir, "blobs")
}

func (md *MinionDaemon) GITREPOS() string {
	return path.Join(md.workdir, "gitrepos")
}

func (md *MinionDaemon) GITCACHE() string {
	return path.Join(md.workdir, "gitcache")
}

func (md *MinionDaemon) TMP() string {
	return path.Join(md.workdir, "tmp")
}

func (md *MinionDaemon) HEADS() string {
	return path.Join(md.workdir, "HEADS")
}

func (md *MinionDaemon) BUILD() string {
	return path.Join(md.workdir, "build")
}

func (md *MinionDaemon) BUILDS() string {
	return path.Join(md.workdir, "builds")
}

func (md *MinionDaemon) PROCESSES() string {
	return path.Join(md.workdir, "processes")
}

func (md *MinionDaemon) MINIONFILE() string {
	return path.Join(md.BUILD(), "Minionfile")
}

func (md *MinionDaemon) TARGETS() string {
	return path.Join(md.workdir, "targets")
}

func (md *MinionDaemon) lockWorkdir() error {
	f, err := os.OpenFile(md.LOCK(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return err
	}
	md.lock = f
	return nil
}

func (md *MinionDaemon) ensureGitCacheExists() error {
	_, err := os.Stat(path.Join(md.GITCACHE(), "config"))
	if err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	cmd := exec.Command("git", "init", "--bare")
	cmd.Dir = md.GITCACHE()
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

////////////////////////////////// Target APIs /////////////////////////////////

func (md *MinionDaemon) isValidTargetName(name string) bool {
	matched, err := regexp.MatchString("^[a-zA-Z0-9_][-a-zA-Z0-9_.]*$", name)
	if err != nil {
		panic(err)
	}
	return matched
}

func (md *MinionDaemon) targetPath(name string) string {
	if !md.isValidTargetName(name) {
		panic(fmt.Errorf("cannot take targetPath of invalid target name"))
	}
	return path.Join(md.TARGETS(), name)
}

func (md *MinionDaemon) targetAutoPath(name string) string {
	return path.Join(md.targetPath(name), "AUTO")
}

func (md *MinionDaemon) targetHeadsPath(name string) string {
	return path.Join(md.targetPath(name), "HEADS")
}

func (md *MinionDaemon) isTarget(name string) bool {
	if !md.isValidTargetName(name) {
		return false
	}
	path := md.targetPath(name)
	_, err := os.Stat(path)
	return err == nil
}

func (md *MinionDaemon) NewTarget(name string) error {
	if !md.isValidTargetName(name) {
		return fmt.Errorf("%s is not a valid target name", name)
	}
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	path := md.targetPath(name)
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("target already exists")
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("could not stat %s: %s", path, err)
	}
	err = os.MkdirAll(path, 0700)
	if err != nil {
		return fmt.Errorf("could not create target: %s", err)
	}
	heads, err := os.Open(md.HEADS())
	if err != nil {
		return fmt.Errorf("could not open heads (sync and retry): %s", err)
	}
	autos, err := os.OpenFile(md.targetAutoPath(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not write heads: %s", err)
	}
	theads, err := os.OpenFile(md.targetHeadsPath(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not write heads: %s", err)
	}
	written_autos, err := io.Copy(autos, heads)
	if err != nil {
		return fmt.Errorf("could not write heads: %s", err)
	}
	_, err = heads.Seek(0, os.SEEK_SET)
	if err != nil {
		return fmt.Errorf("could not write heads: %s", err)
	}
	written_heads, err := io.Copy(theads, heads)
	if err != nil {
		return fmt.Errorf("could not write heads: %s", err)
	}
	if written_autos != written_heads {
		return fmt.Errorf("error copying heads (rm target and try again): %s", err)
	}
	return nil
}

func (md *MinionDaemon) DelTarget(name string) error {
	if !md.isValidTargetName(name) {
		return fmt.Errorf("%s is not a valid target name", name)
	}
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	path := md.targetPath(name)
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("target does not exist")
	} else if err != nil {
		return err
	}
	return os.RemoveAll(md.targetPath(name))
}

func (md *MinionDaemon) listTargets() ([]string, error) {
	files, err := ioutil.ReadDir(md.TARGETS())
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for _, fi := range files {
		if md.isValidTargetName(fi.Name()) {
			names = append(names, fi.Name())
		}
	}
	return names, nil
}

func (md *MinionDaemon) ListTargets() ([]string, error) {
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	return md.listTargets()
}

/////////////////////////////// Source Code Sync ///////////////////////////////

func (md *MinionDaemon) parseHeads(path string) (map[string]HeadPtr, error) {
	heads := make(map[string]HeadPtr)
	f, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return heads, nil
	} else if err != nil {
		return heads, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pieces := strings.Split(scanner.Text(), ": ")
		if len(pieces) != 2 {
			return heads, fmt.Errorf("invalid file format")
		}
		name := pieces[0]
		pieces = strings.SplitN(pieces[1], " ", 2)
		if pieces[0] != "-" && pieces[1] != "-" {
			heads[name] = HeadPtr{pieces[0], pieces[1]}
		}
	}
	if err = scanner.Err(); err != nil {
		return heads, err
	}
	return heads, nil
}

func (md *MinionDaemon) writeHeads(path string, sources []Source, heads map[string]HeadPtr) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, src := range sources {
		if head, ok := heads[src.Name()]; ok {
			_, err = f.WriteString(fmt.Sprintf("%s: %s %s\n", src.Name(), head.RefSpec, head.RefName))
			if err != nil {
				return err
			}
		} else {
			_, err = f.WriteString(fmt.Sprintf("%s: - -\n", src.Name()))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (md *MinionDaemon) updateFetchSource(fs FetchSource) (HeadPtr, error) {
	if len(fs.hash) > 0 && md.blobs.Has(BlobID(fs.hash)) {
		return HeadPtr{fs.hash, fs.name}, nil
	}
	tmpdir, err := ioutil.TempDir(md.TMP(), "minion-fetch-")
	if err != nil {
		return HeadPtr{}, err
	}
	path := path.Join(tmpdir, "fetched")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return HeadPtr{}, err
	}
	resp, err := http.Get(fs.url)
	if err != nil {
		return HeadPtr{}, err
	}
	defer resp.Body.Close()
	defer os.RemoveAll(tmpdir)
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return HeadPtr{}, err
	}
	bid, err := md.blobs.Add(path)
	if err != nil {
		return HeadPtr{}, err
	}
	if len(fs.hash) > 0 && BlobID(fs.hash) != bid {
		return HeadPtr{}, fmt.Errorf("checksum mismatch on source %s", fs.Name())
	}
	return HeadPtr{fs.hash, fs.name}, nil
}

func (md *MinionDaemon) updateGitSourceRefSpec(gs GitSource, rs string) (HeadPtr, error) {
	repo := path.Join(md.GITREPOS(), gs.Name())
	err := os.RemoveAll(repo)
	if err != nil {
		return HeadPtr{}, err
	}
	env := make([]string, 0)
	env = append(env, fmt.Sprintf("GIT_DIR=%s", md.GITCACHE()))
	if val, has := os.LookupEnv("SSH_AUTH_SOCK"); has {
		env = append(env, fmt.Sprintf("SSH_AUTH_SOCK=%s", val))
	}
	if val, has := os.LookupEnv("SSH_AGENT_PID"); has {
		env = append(env, fmt.Sprintf("SSH_AGENT_PID=%s", val))
	}
	// remove old remote
	cmd := exec.Command("git", "remote", "rm", gs.Name())
	cmd.Env = env
	cmd.Run() // do not care if fails
	// add new remote
	cmd = exec.Command("git", "remote", "add", gs.Name(), gs.url)
	cmd.Env = env
	if err = cmd.Run(); err != nil {
		return HeadPtr{}, err
	}
	// fetch source
	cmd = exec.Command("git", "fetch", gs.Name())
	cmd.Env = env
	if err = cmd.Run(); err != nil {
		return HeadPtr{}, err
	}
	// clone to repo
	cmd = exec.Command("git", "clone", "--mirror", "--shared", "--reference",
		md.GITCACHE(), gs.url, repo)
	cmd.Env = env
	if err = cmd.Run(); err != nil {
		return HeadPtr{}, err
	}
	// get refspec
	env[0] = fmt.Sprintf("GIT_DIR=%s", repo)
	cmd = exec.Command("git", "rev-list", "-n", "1", rs)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return HeadPtr{}, err
	}
	return HeadPtr{strings.TrimSpace(string(out)), rs}, nil
}

func (md *MinionDaemon) updateGitSource(gs GitSource) (HeadPtr, error) {
	if len(gs.branch) > 0 {
		return md.updateGitSourceRefSpec(gs, gs.branch)
	} else {
		return md.updateGitSourceRefSpec(gs, "master")
	}
}

func (md *MinionDaemon) syncTarget(name string, sources []Source, updated map[string]HeadPtr) error {
	autos_path := md.targetAutoPath(name)
	heads_path := md.targetHeadsPath(name)
	autos, err := md.parseHeads(autos_path)
	if err != nil {
		return err
	}
	heads, err := md.parseHeads(heads_path)
	if err != nil {
		return err
	}
	for k, v := range updated {
		auto_val, auto_ok := autos[k]
		head_val, head_ok := heads[k]
		if !auto_ok {
			auto_val = v
		}
		if !head_ok {
			head_val = v
			heads[k] = v
		}
		if HeadPtrsSame(auto_val, head_val) && !HeadPtrsSame(auto_val, v) {
			heads[k] = v
		}
		autos[k] = v
	}
	err = md.writeHeads(autos_path, sources, autos)
	if err != nil {
		return err
	}
	err = md.writeHeads(heads_path, sources, heads)
	if err != nil {
		return err
	}
	return nil
}

func (md *MinionDaemon) SyncSources(sources []string) ([]string, []string, []string, error) {
	removed := make([]string, 0)
	changed := make([]string, 0)
	added := make([]string, 0)
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	// get the Minionfile in parsed form
	mf, err := ParseMinionfile(md.MINIONFILE())
	if err != nil {
		return removed, changed, added, fmt.Errorf("could not parse minionfile: %s", err)
	}
	// make sure that every source named actually exists
	for _, name := range sources {
		if mf.GetSource(name) == nil {
			return removed, changed, added, fmt.Errorf("unknown source %s", name)
		}
	}
	// default is to update everything if request is to update nothing
	if len(sources) == 0 {
		sources = make([]string, 0, len(mf.Sources))
		for _, src := range mf.Sources {
			sources = append(sources, src.Name())
		}
	}
	// get the old heads
	old_heads, err := md.parseHeads(md.HEADS())
	if err != nil {
		return removed, changed, added, fmt.Errorf("could not parse heads: %s", err)
	}
	// update each source listed
	new_heads := make(map[string]HeadPtr)
	for _, name := range sources {
		src := mf.GetSource(name)
		ptr, err := src.Update(md)
		if err != nil {
			return removed, changed, added, fmt.Errorf("could not update head %s: %s", src.Name(), err)
		}
		new_heads[name] = ptr
	}
	// copy each head from old_heads to new_heads if not updated
	for name, ptr := range old_heads {
		if mf.GetSource(name) == nil {
			continue
		}
		if _, ok := new_heads[name]; !ok {
			new_heads[name] = ptr
		}
	}
	// compute changed/removed heads
	for name, old_ptr := range old_heads {
		new_ptr, ok := new_heads[name]
		if ok && old_ptr.RefSpec != new_ptr.RefSpec {
			changed = append(changed, name)
		} else if !ok {
			removed = append(removed, name)
		}
	}
	// compute added heads
	for name, _ := range new_heads {
		if _, ok := old_heads[name]; !ok {
			added = append(added, name)
		}
	}
	// write the new heads
	err = md.writeHeads(md.HEADS(), mf.Sources, new_heads)
	if err != nil {
		return removed, changed, added, fmt.Errorf("could not write HEADS: %s", err)
	}
	// sync every target to the new heads
	targets, err := md.listTargets()
	if err != nil {
		return removed, changed, added, fmt.Errorf("could not list targets: %s", err)
	}
	for _, target := range targets {
		err = md.syncTarget(target, mf.Sources, new_heads)
		if err != nil {
			return removed, changed, added, fmt.Errorf("could not sync target %s: %s", target, err)
		}
	}
	return removed, changed, added, nil
}

func (md *MinionDaemon) TargetSetRefSpec(target string, source string, refspec string) error {
	// make sure we're looking for a good target
	if !md.isValidTargetName(target) {
		return fmt.Errorf("%s is not a valid target name", target)
	}
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	// make sure the target exists
	if !md.isTarget(target) {
		return fmt.Errorf("target %s does not exist", target)
	}
	// get the Minionfile in parsed form
	mf, err := ParseMinionfile(md.MINIONFILE())
	// check that the source requested is a good one
	src := mf.GetSource(source)
	if src == nil {
		return fmt.Errorf("source %s does not exist", source)
	}
	src, ok := src.(GitSource)
	if !ok {
		return fmt.Errorf("cannot set refspec for non-git source")
	}
	// get the HEADS
	heads, err := md.parseHeads(md.targetHeadsPath(target))
	if err != nil {
		return fmt.Errorf("could not parse heads: %s", err)
	}
	// udpate the refspec
	ptr, err := md.updateGitSourceRefSpec(src.(GitSource), refspec)
	if err != nil {
		return fmt.Errorf("could not switch to refspec: %s", err)
	}
	heads[source] = ptr
	// write the new heads
	err = md.writeHeads(md.targetHeadsPath(target), mf.Sources, heads)
	if err != nil {
		return fmt.Errorf("could not write HEADS: %s", err)
	}
	return nil
}

/////////////////////////////// Build Management ///////////////////////////////

type BuildInfo struct {
	Target string
	Name   string
	Time   time.Time
}

func (md *MinionDaemon) ListBuilds() ([]BuildInfo, error) {
	files, err := ioutil.ReadDir(md.BUILDS())
	if err != nil {
		return nil, err
	}
	builds := make([]BuildInfo, 0, len(files))
	for _, fi := range files {
		pieces := strings.SplitN(fi.Name(), ":", 2)
		if len(pieces) != 2 {
			continue
		}
		target := pieces[0]
		time, err := time.Parse("2006-01-02T15:04:05Z", pieces[1])
		if err != nil {
			time = fi.ModTime().UTC()
		}
		builds = append(builds, BuildInfo{target, pieces[1], time})
	}
	md.buildsMtx.Lock()
	defer md.buildsMtx.Unlock()
	for b, _ := range md.builds {
		builds = append(builds, b)
	}
	return builds, nil
}

func (md *MinionDaemon) IdentifyLatestBuild(target string) (build BuildInfo, err error) {
	builds, err := md.ListBuilds()
	if err != nil {
		return
	}
	for _, b := range builds {
		if build.Time.Before(b.Time) {
			build = b
		}
	}
	return
}

func (md *MinionDaemon) GetBuild(target string, build_name string) (*BuildReport, error) {
	var br BuildReport
	p := path.Join(md.BUILDS(), fmt.Sprintf("%s:%s", target, build_name))
	buf, err := ioutil.ReadFile(p)
	if err != nil {
		return &br, err
	}
	if err = json.Unmarshal(buf, &br); err != nil {
		return &br, err
	}
	return &br, nil
}

func (md *MinionDaemon) GetArtifacts(target string, build_name string, dir string) error {
	br, err := md.GetBuild(target, build_name)
	if err != nil {
		return err
	}
	for _, rep := range br.Reports {
		for art, ptr := range rep.Artifacts {
			p := path.Join(dir, art.Display(), ptr.Path)
			d := path.Dir(p)
			err = os.MkdirAll(d, 0700)
			if err != nil {
				return fmt.Errorf("could not create directory: %s", err)
			}
			err = md.blobs.CopyTo(ptr.Blob, p)
			if err != nil {
				return fmt.Errorf("could not copy artifacts: %s", err)
			}
		}
	}
	return nil
}

func (md *MinionDaemon) preBuild(target string, build_name string, _processes []string) (mbid BlobID, hbid BlobID, mf Minionfile, processes []string, heads map[string]HeadPtr, err error) {
	// make sure we're looking for a good target
	if !md.isValidTargetName(target) {
		err = fmt.Errorf("%s is not a valid target name", target)
		return
	}
	// make sure we don't override the "latest" meta-build
	if build_name == "latest" {
		err = fmt.Errorf("cannot have a build named \"latest\"")
		return
	}
	md.headsMtx.Lock()
	defer md.headsMtx.Unlock()
	// make sure the target exists
	if !md.isTarget(target) {
		err = fmt.Errorf("target %s does not exist", target)
		return
	}
	// XXX make sure build doesn't exist
	// snapshot minionfile
	mbid, err = md.blobs.Add(md.MINIONFILE())
	if err != nil {
		err = fmt.Errorf("could not snapshot Minionfile: %s", err)
		return
	}
	// snapshot HEADS
	hbid, err = md.blobs.Add(md.targetHeadsPath(target))
	if err != nil {
		err = fmt.Errorf("could not snapshot Minionfile: %s", err)
		return
	}
	// get the Minionfile in parsed form
	mf, err = ParseMinionfile(md.blobs.Path(mbid))
	if err != nil {
		err = fmt.Errorf("could not parse Minionfile: %s", err)
		return
	}
	// make sure that every process named actually exists
	processes = _processes
	for _, name := range processes {
		if mf.GetProcess(name) == nil {
			err = fmt.Errorf("unknown process %s", name)
			return
		}
	}
	// default is to update everything if request is to update nothing
	if len(processes) != len(mf.Processes) && len(processes) != 0 {
		panic(fmt.Errorf("not implemented")) // XXX
	}
	if len(processes) == 0 {
		processes = make([]string, 0, len(mf.Processes))
		for _, proc := range mf.Processes {
			processes = append(processes, proc.Name())
		}
	}
	// get the HEADS
	heads, err = md.parseHeads(md.blobs.Path(hbid))
	if err != nil {
		err = fmt.Errorf("could not parse heads: %s", err)
		return
	}
	err = nil
	return
}

func (md *MinionDaemon) Build(target string, build_name string, retry_failures bool, processes []string) (*BuildReport, error) {
	mbid, hbid, mf, processes, heads, err := md.preBuild(target, build_name, processes)
	if err != nil {
		return nil, err
	}
	buildMtx := &sync.Mutex{}
	buildCnd := sync.NewCond(buildMtx)
	build := Build{BuildInfo: BuildInfo{Target: target,
		Name: build_name,
		Time: time.Now()},
		mbid:      mbid,
		hbid:      hbid,
		md:        md,
		mf:        mf,
		heads:     heads,
		retry:     retry_failures,
		procs:     processes,
		buildMtx:  buildMtx,
		buildCnd:  buildCnd,
		failed:    len(processes),
		artifacts: make(ArtifactMap),
		reports:   make(map[string]ProcessReport)}
	md.buildsMtx.Lock()
	md.builds[build.BuildInfo] = &build
	md.buildsMtx.Unlock()
	br, err := build.Run()
	md.buildsMtx.Lock()
	delete(md.builds, build.BuildInfo)
	md.buildsMtx.Unlock()
	return br, err
}

func (md *MinionDaemon) isCached(iid BlobID) (BlobID, bool) {
	return md.procCache.Lookup(iid)
}

func (md *MinionDaemon) readProcessReport(oid BlobID) (pr ProcessReport, err error) {
	pr.Artifacts = make(ArtifactMap)
	f, err := os.Open(md.blobs.Path(oid))
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid process report")
	scanner := bufio.NewScanner(f)
	var name string
	for scanner.Scan() {
		pieces := strings.Split(scanner.Text(), ": ")
		if len(pieces) != 2 {
			return
		}
		field := pieces[0]
		switch field {
		case "process":
			name = pieces[1]
		case "inputs":
			pr.Inputs = BlobID(pieces[1])
		case "status":
			switch pieces[1] {
			case "success":
				pr.Status = SUCCESS
			case "failed":
				pr.Status = FAILED
			case "error":
				pr.Status = ERROR
			case "skipped":
				pr.Status = SKIPPED
			case "run":
				pr.Status = NOT_RUN
			default:
				return
			}
		case "cached":
			pr.Cached = pieces[1] == "true"
		case "released":
			pr.Released = pieces[1] == "true"
		case "status-msg":
			var tmp []byte
			tmp, err = md.blobs.Dump(BlobID(pieces[1]))
			if err != nil {
				err = fmt.Errorf("dangling reference to %s", pieces[1])
				return
			}
			pr.StatusMsg = string(tmp)
		case "log":
			var tmp []byte
			tmp, err = md.blobs.Dump(BlobID(pieces[1]))
			if err != nil {
				err = fmt.Errorf("dangling reference to %s", pieces[1])
				return
			}
			pr.Log = string(tmp)
		case "artifact":
			pieces = strings.Split(pieces[1], " ")
			if len(pieces) != 3 {
				return
			}
			pr.Artifacts[Artifact{name, pieces[0]}] = ArtifactPtr{BlobID(pieces[1]), pieces[2]}
		default:
			return
		}
	}
	return
}

func (md *MinionDaemon) writeProcessReport(proc Process, pr ProcessReport) (BlobID, error) {
	f, err := ioutil.TempFile(md.TMP(), "process-report-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	_, err = fmt.Fprintf(f, "process: %s\n", proc.Name())
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(f, "inputs: %s\n", pr.Inputs)
	if err != nil {
		return "", err
	}
	switch pr.Status {
	case SUCCESS:
		_, err = fmt.Fprintf(f, "status: success\n")
	case FAILED:
		_, err = fmt.Fprintf(f, "status: failed\n")
	case ERROR:
		_, err = fmt.Fprintf(f, "status: error\n")
	case SKIPPED:
		_, err = fmt.Fprintf(f, "status: skipped\n")
	case NOT_RUN:
		_, err = fmt.Fprintf(f, "status: not run\n")
	default:
		return "", err
	}
	if err != nil {
		return "", err
	}
	if pr.Cached {
		_, err := fmt.Fprintf(f, "cached: true\n")
		if err != nil {
			return "", err
		}
	} else {
		_, err := fmt.Fprintf(f, "cached: false\n")
		if err != nil {
			return "", err
		}
	}
	if pr.Released {
		_, err := fmt.Fprintf(f, "released: true\n")
		if err != nil {
			return "", err
		}
	} else {
		_, err := fmt.Fprintf(f, "released: false\n")
		if err != nil {
			return "", err
		}
	}
	var bid BlobID
	bid, err = md.blobs.Cat([]byte(pr.StatusMsg))
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(f, "status-msg: %s\n", bid)
	bid, err = md.blobs.Cat([]byte(pr.Log))
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(f, "log: %s\n", bid)
	for art, ptr := range pr.Artifacts {
		_, err := fmt.Fprintf(f, "artifact: %s %s %s\n", art.Name, ptr.Blob, ptr.Path)
		if err != nil {
			return "", err
		}
	}
	return md.blobs.Add(f.Name())
}

type ArtifactMap map[Artifact]ArtifactPtr

func (a ArtifactMap) MarshalJSON() ([]byte, error) {
	bystr := make(map[string]ArtifactPtr)
	for art, ptr := range a {
		bystr[art.Display()] = ptr
	}
	return json.Marshal(bystr)
}

func (a *ArtifactMap) UnmarshalJSON(text []byte) error {
	*a = make(ArtifactMap)
	var bystr map[string]ArtifactPtr
	err := json.Unmarshal(text, &bystr)
	if err != nil {
		return err
	}
	for k := range *a {
		delete(*a, k)
	}
	for k, v := range bystr {
		pieces := strings.Split(k, "=>")
		if len(pieces) != 2 {
			return fmt.Errorf("invalid artifact")
		}
		(*a)[Artifact{pieces[0], pieces[1]}] = v
	}
	return nil
}

type Build struct {
	BuildInfo
	mbid      BlobID
	hbid      BlobID
	md        *MinionDaemon
	mf        Minionfile
	heads     map[string]HeadPtr
	retry     bool
	procs     []string
	buildMtx  *sync.Mutex
	buildCnd  *sync.Cond
	failed    int
	artifacts ArtifactMap
	reports   map[string]ProcessReport
}

type ProcessStatus int

const (
	SUCCESS ProcessStatus = iota
	FAILED
	ERROR
	NOT_RUN
	SKIPPED
)

func (ps ProcessStatus) String() string {
	switch ps {
	case SUCCESS:
		return "SUCCESS"
	case FAILED:
		return "FAILED"
	case ERROR:
		return "ERROR"
	case NOT_RUN:
		return "NOT_RUN"
	case SKIPPED:
		return "SKIPPED"
	default:
		return "UNKNOWN"
	}
}

type ProcessReport struct {
	Status    ProcessStatus
	Cached    bool
	Released  bool
	StatusMsg string
	Log       string
	Inputs    BlobID
	Artifacts ArtifactMap
}

func (p ProcessReport) IsSuccess() bool {
	return p.Status == SUCCESS || p.Status == SKIPPED
}

type Processor interface {
	BuildIt(map[string]HeadPtr, ArtifactMap) ProcessReport
}

func (bd *Build) processIndex(proc Process) int {
	for idx, name := range bd.procs {
		if proc.Name() == name {
			return idx
		}
	}
	return len(bd.procs)
}

func (bd *Build) waitForDependencies(proc Process) (bool, map[string]HeadPtr, ArtifactMap) {
	idx := bd.processIndex(proc)
	bd.buildMtx.Lock()
	defer bd.buildMtx.Unlock()
	// loop until dependencies are satisfied or an error is encountered
	for {
		sources := make(map[string]HeadPtr)
		artifacts := make(ArtifactMap)
		// a lower process failed
		if bd.failed < idx {
			return false, sources, artifacts
		}
		wait := false
		// for each dependency
		for _, dep := range proc.Dependencies() {
			// if source exists, capture it; else error
			if s, ok := dep.(SourceDependency); ok {
				if ptr, ok := bd.heads[s.name]; ok {
					sources[s.name] = ptr
				} else {
					return false, sources, artifacts
				}
				// if artifact exists, capture it; else wait
			} else if a, ok := dep.(ArtifactDependency); ok {
				if bid, ok := bd.artifacts[a.Artifact]; ok {
					artifacts[a.Artifact] = bid
				} else {
					wait = true
				}
			} else {
				panic(fmt.Errorf("unhandled dependency type"))
			}
		}
		// wait or return results
		if !wait {
			return true, sources, artifacts
		} else {
			bd.buildCnd.Wait()
		}
	}
}

func (bd *Build) addReport(proc Process, report ProcessReport) {
	bd.buildMtx.Lock()
	defer bd.buildMtx.Unlock()
	bd.reports[proc.Name()] = report
	failed := false
	if IsBlobID(report.Inputs) {
		oid, err := bd.md.writeProcessReport(proc, report)
		if err == nil && (report.Status == SUCCESS || report.Status == FAILED) {
			err = bd.md.procCache.Insert(report.Inputs, oid)
			if err != nil {
				failed = true
			}
		} else {
			failed = true
		}
	} else {
		failed = true
	}
	if report.IsSuccess() {
		for art, ptr := range report.Artifacts {
			if _, ok := bd.artifacts[art]; ok {
				panic(fmt.Errorf("multiple processes generate artifact %s", art.Display()))
			}
			bd.artifacts[art] = ptr
		}
	} else {
		failed = true
	}
	if failed {
		idx := bd.processIndex(proc)
		if idx < bd.failed {
			bd.failed = idx
		}
	}
	bd.buildCnd.Broadcast()
}

func (bd *Build) runProc(proc Process, wg *sync.WaitGroup) {
	defer wg.Done()
	proceed, heads, artifacts := bd.waitForDependencies(proc)
	report := ProcessReport{Status: NOT_RUN,
		StatusMsg: "dependencies not satisfied"}
	if proceed {
		report = proc.Processor(bd).BuildIt(heads, artifacts)
	}
	bd.addReport(proc, report)
}

func (bd *Build) Run() (*BuildReport, error) {
	wg := sync.WaitGroup{}
	wg.Add(len(bd.procs))
	for _, name := range bd.procs {
		proc := bd.mf.GetProcess(name)
		go bd.runProc(proc, &wg)
	}
	wg.Wait()
	bd.buildMtx.Lock()
	defer bd.buildMtx.Unlock()
	for _, name := range bd.procs {
		if _, ok := bd.reports[name]; !ok {
			bd.reports[name] = ProcessReport{Status: ERROR,
				StatusMsg: "processor did not report status"}
		}
	}
	procs := make([]string, 0, len(bd.mf.Processes))
	for _, proc := range bd.mf.Processes {
		procs = append(procs, proc.Name())
	}
	br := &BuildReport{BuildInfo: bd.BuildInfo,
		Processes: procs,
		Reports:   bd.reports}
	txt, err := json.Marshal(br)
	if err != nil {
		return br, err
	}
	f, err := ioutil.TempFile(bd.md.TMP(), "process-report-")
	if err != nil {
		return br, err
	}
	defer f.Close()
	n, err := f.Write(txt)
	if err != nil {
		return br, err
	}
	if n != len(txt) {
		return br, fmt.Errorf("could not write build: short write")
	}
	err = f.Sync()
	if err != nil {
		return br, err
	}
	p := path.Join(bd.md.BUILDS(), fmt.Sprintf("%s:%s", bd.BuildInfo.Target, bd.BuildInfo.Name))
	err = os.Rename(f.Name(), p)
	return br, err
}
