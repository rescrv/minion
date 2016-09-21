package minion

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sync"
)

type BlobID string

type BlobStore struct {
	base  string
	mutex sync.Mutex
}

func IsBlobID(bid BlobID) bool {
	return len(bid) == 64 // XXX make this tighter to check hex
}

func NewBlobStore(blobdir string) *BlobStore {
	return &BlobStore{blobdir, sync.Mutex{}}
}

// Add adds a file to the blob store and returns a BlobID that can be used to
// retrieve the blob in the future.
func (bs *BlobStore) Add(path string) (bid BlobID, err error) {
	src, err := os.Open(path)
	if err != nil {
		return
	}
	tmp, err := ioutil.TempFile(bs.base, "blob-")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	buf := make([]byte, 4096, 4096)
	for {
		amtr, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return BlobID(""), err
		}
		if amtr == 0 {
			break
		}
		h.Write(buf[:amtr])
		amtw, err := tmp.Write(buf[:amtr])
		if err != nil {
			return BlobID(""), err
		} else if amtr != amtw {
			err = errors.New("short write")
			return BlobID(""), err
		}
	}
	hashbin := make([]byte, 0, 64)
	hashbin = h.Sum(hashbin)
	hashhex := hex.EncodeToString(hashbin)
	bs.mutex.Lock()
	defer bs.mutex.Unlock()
	bid = BlobID(hashhex)
	dst := bs.sha256path(bid)
	os.MkdirAll(filepath.Dir(dst), 0700)
	if _, e := os.Stat(dst); e != nil {
		err = os.Link(tmp.Name(), dst)
		if err != nil {
			return
		}
	}
	return bid, nil
}

// Cat takes the provided contents, writes it to a file, and adds it to the
// blobstore.  Return values are the same as Add.
func (bs *BlobStore) Cat(content []byte) (bid BlobID, err error) {
	tmp, err := ioutil.TempFile(bs.base, "blob-")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	amt, err := tmp.Write(content)
	if err != nil {
		return
	}
	if amt != len(content) {
		err = errors.New("short write")
		return
	}
	tmp.Sync()
	return bs.Add(tmp.Name())
}

func (bs *BlobStore) Dump(bid BlobID) ([]byte, error) {
	return ioutil.ReadFile(bs.sha256path(bid))
}

func (bs *BlobStore) CopyTo(bid BlobID, path string) error {
	src, err := os.Open(bs.sha256path(bid))
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	return err
}

func (bs *BlobStore) Has(bid BlobID) bool {
	_, err := os.Stat(bs.sha256path(bid))
	return err == nil
}

func (bs *BlobStore) Path(bid BlobID) string {
	return bs.sha256path(bid)
}

func (bs *BlobStore) sha256path(bid BlobID) string {
	bytes := []byte(bid)
	if len(bytes) != 64 {
		panic("improper hash used in the blob store")
	}
	a := string(bytes[0:2])
	b := string(bytes[2:4])
	c := string(bytes[4:])
	return path.Join(bs.base, a, b, c)
}
