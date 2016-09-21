package minion

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type ProcessCache struct {
	base string
}

func NewProcessCache(procdir string) *ProcessCache {
	return &ProcessCache{procdir}
}

func (pc *ProcessCache) Lookup(inputs BlobID) (BlobID, bool) {
	f, err := os.Open(pc.path(inputs))
	if err != nil {
		return "", false
	}
	buf := make([]byte, 64, 128)
	_, err = io.ReadAtLeast(f, buf, 64)
	if err != nil {
		return "", false
	}
	o := strings.TrimSpace(string(buf))
	return BlobID(o), len(o) == 64
}

func (pc *ProcessCache) Insert(inputs BlobID, outputs BlobID) error {
	tmp, err := ioutil.TempFile(pc.base, "proc-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	amt, err := tmp.Write([]byte(outputs))
	if err != nil {
		return err
	}
	if amt != len(outputs) {
		err = errors.New("short write")
		return err
	}
	tmp.Sync()
	dst := pc.path(inputs)
	err = os.MkdirAll(filepath.Dir(dst), 0700)
	if err != nil {
		return err
	}
	err = os.Rename(tmp.Name(), dst)
	if err != nil {
		return err
	}
	return nil
}

func (pc *ProcessCache) Forget(inputs BlobID) error {
	err := os.Remove(pc.path(inputs))
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (pc *ProcessCache) path(inputs BlobID) string {
	bytes := []byte(inputs)
	if len(bytes) != 64 {
		panic("improper hash used in the process cache")
	}
	a := string(bytes[0:2])
	b := string(bytes[2:4])
	c := string(bytes[4:])
	return path.Join(pc.base, a, b, c)
}
