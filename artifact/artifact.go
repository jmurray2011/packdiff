// SPDX-License-Identifier: Apache-2.0

// Package artifact walks release artifacts (RPM, DEB, WAR/JAR/ZIP, tar.gz) into snapshots.
// It reads only; nothing inside an artifact is executed.
package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

// ErrUnsupported reports an input that is not a recognized artifact type.
var ErrUnsupported = errors.New("unsupported artifact")

// ErrUnsafePath reports an entry name that would land outside the extraction root.
var ErrUnsafePath = errors.New("unsafe entry path")

// ErrTooLarge reports content that exceeds the walk's memory limits.
var ErrTooLarge = errors.New("entry too large")

// ErrTooDeep reports archives nested deeper than the walk allows.
var ErrTooDeep = errors.New("archives nested too deeply")

// limits bound the memory one walk can use on hostile or broken input.
type limits struct {
	depth  int   // archive levels below the artifact that are walked
	nested int64 // one nested archive held in memory; larger ones are recorded, not walked
	live   int64 // nested archives held in memory at once, along the current chain
	keep   int64 // one entry's kept content; larger entries keep none
	kept   int64 // all kept content in one snapshot
}

// keep is sized for large bundles' source maps, which run to tens of megabytes.
var defaultLimits = limits{depth: 8, nested: 512 << 20, live: 1 << 30, keep: 32 << 20, kept: 1 << 30}

// Unix st_mode type bits.
const (
	modeDir  = 0o040000
	modeReg  = 0o100000
	modeLink = 0o120000
)

// Options controls a walk.
type Options struct {
	// Want selects entries whose content is kept in the snapshot.
	Want core.Wants
	// ExtractTo, when set, receives the payload's regular files (not nested entries).
	ExtractTo string
}

// Open fingerprints the artifact at p and walks it.
func Open(ctx context.Context, p string, opts Options) (core.Snapshot, error) {
	return open(ctx, p, opts, defaultLimits)
}

func open(ctx context.Context, p string, opts Options, lim limits) (core.Snapshot, error) {
	f, err := os.Open(p)
	if err != nil {
		return core.Snapshot{}, err
	}
	defer func() { _ = f.Close() }() // read-only

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return core.Snapshot{}, fmt.Errorf("hash %s: %w", p, err)
	}
	head := make([]byte, 512)
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return core.Snapshot{}, err
	}
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return core.Snapshot{}, err
	}

	base := filepath.Base(p)
	w := &walker{ctx: ctx, want: opts.Want, extractTo: opts.ExtractTo, lim: lim}
	s := core.Snapshot{Artifact: core.Artifact{Path: p, SHA256: hex.EncodeToString(h.Sum(nil))}}
	switch {
	case bytes.HasPrefix(head, []byte{0xed, 0xab, 0xee, 0xdb}):
		s.Artifact.Type = "rpm"
		err = w.rpm(f, base, &s)
	case bytes.HasPrefix(head, []byte("!<arch>\n")):
		s.Artifact.Type = "deb"
		err = w.deb(f, base, &s)
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		s.Artifact.Type = zipType(base)
		s.Artifact.Name, s.Artifact.Version = nameVersion(base)
		err = w.zip([]string{base}, f, size)
	case tarballType(head) != "":
		s.Artifact.Type = tarballType(head)
		s.Artifact.Name, s.Artifact.Version = nameVersion(base)
		var r io.Reader
		if r, err = decompress(s.Artifact.Type, f); err == nil {
			err = w.tar([]string{base}, r, nil, true)
		}
	default:
		// A zip behind a launch script, as in self-executing jars.
		if _, zerr := zip.NewReader(f, size); zerr != nil {
			return core.Snapshot{}, fmt.Errorf("%w: %s", ErrUnsupported, base)
		}
		s.Artifact.Type = zipType(base)
		s.Artifact.Name, s.Artifact.Version = nameVersion(base)
		err = w.zip([]string{base}, f, size)
	}
	if err != nil {
		return core.Snapshot{}, fmt.Errorf("walk %s: %w", base, err)
	}
	s.Files = w.files
	return s, nil
}

type walker struct {
	ctx       context.Context
	want      core.Wants
	extractTo string
	lim       limits
	live      int64 // bytes of nested archives currently held
	kept      int64 // bytes of content kept so far
	copyBuf   []byte
	files     []core.File
}

// sink opens the extraction target for a payload entry, or returns nil when not extracting.
func (w *walker) sink(chain []string) (*os.File, error) {
	if w.extractTo == "" || len(chain) != 2 {
		return nil, nil
	}
	if !filepath.IsLocal(chain[1]) {
		return nil, fmt.Errorf("%w: %s", ErrUnsafePath, chain[1])
	}
	dst := filepath.Join(w.extractTo, filepath.FromSlash(chain[1]))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

func isArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear", ".zip":
		return true
	}
	return isTarball(name)
}

var tarballSuffixes = []string{".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tzst", ".tar.bz2", ".tbz2"}

func isTarball(name string) bool {
	name = strings.ToLower(name)
	for _, s := range tarballSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// tarballType names a tar stream by its leading bytes, or returns "".
func tarballType(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "tar.gz"
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		return "tar.xz"
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "tar.zst"
	case bytes.HasPrefix(head, []byte("BZh")):
		return "tar.bz2"
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// entry records one regular file, keeping its content when wanted and walking it when nested.
func (w *walker) entry(f core.File, r io.Reader) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	out, err := w.sink(f.Chain)
	if err != nil {
		return err
	}
	if out != nil {
		defer func() { _ = out.Close() }() // error paths only; success closes and checks below
	}
	h := sha256.New()
	var sum io.Writer = h
	if out != nil {
		sum = io.MultiWriter(h, out)
	}
	name := strings.Join(f.Chain, "!")
	nested := isArchive(f.Chain[len(f.Chain)-1]) && f.Size <= w.lim.nested
	if nested && len(f.Chain)-1 > w.lim.depth {
		return fmt.Errorf("%w: %s is %d levels deep", ErrTooDeep, name, len(f.Chain)-1)
	}
	keep := w.want(f.Chain) && f.Size <= w.lim.keep
	var buf []byte
	if nested || keep {
		limit := w.lim.keep
		if nested {
			limit = w.lim.nested
		}
		var err error
		if buf, err = readAll(r, f.Size, limit); err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if int64(len(buf)) > limit {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, name, limit)
		}
		if _, err := sum.Write(buf); err != nil {
			return err
		}
		f.Size = int64(len(buf))
	} else {
		if w.copyBuf == nil {
			w.copyBuf = make([]byte, 256<<10)
		}
		n, err := io.CopyBuffer(sum, r, w.copyBuf)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		f.Size = n
	}
	if out != nil {
		if err := out.Close(); err != nil {
			return err
		}
	}
	f.SHA256 = hex.EncodeToString(h.Sum(nil))
	if keep {
		if w.kept += int64(len(buf)); w.kept > w.lim.kept {
			return fmt.Errorf("%w: kept content passes %d bytes at %s", ErrTooLarge, w.lim.kept, name)
		}
		f.Content = buf
	}
	w.files = append(w.files, f)
	if !nested {
		return nil
	}
	if w.live += int64(len(buf)); w.live > w.lim.live {
		return fmt.Errorf("%w: nested archives held in memory pass %d bytes at %s", ErrTooLarge, w.lim.live, name)
	}
	defer func() { w.live -= int64(len(buf)) }()
	if !isTarball(f.Name()) {
		return w.zip(f.Chain, bytes.NewReader(buf), int64(len(buf)))
	}
	stream, terr := decompress(f.Name(), bytes.NewReader(buf))
	if terr == nil {
		terr = w.tar(f.Chain, stream, nil, false)
	}
	// Like a misnamed zip, a file named like a tarball that is not one is recorded, not walked.
	if errors.Is(terr, tar.ErrHeader) || errors.Is(terr, gzip.ErrHeader) || errors.Is(terr, io.ErrUnexpectedEOF) {
		return nil
	}
	return terr
}

// readAll reads up to limit+1 bytes, sizing the buffer from the declared size so large
// entries are not regrown and copied repeatedly.
func readAll(r io.Reader, declared, limit int64) ([]byte, error) {
	var b bytes.Buffer
	b.Grow(int(min(max(declared, 0), limit) + bytes.MinRead))
	_, err := b.ReadFrom(io.LimitReader(r, limit+1))
	return b.Bytes(), err
}

func (w *walker) zip(chain []string, r io.ReaderAt, size int64) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		// A file named like an archive that is not one is still recorded; it is just not walked.
		if len(chain) > 1 && errors.Is(err, zip.ErrFormat) {
			return nil
		}
		return fmt.Errorf("%s: %w", strings.Join(chain, "!"), err)
	}
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("%s!%s: %w", strings.Join(chain, "!"), zf.Name, err)
		}
		err = w.entry(core.File{
			Chain: appendChain(chain, clean(zf.Name)),
			Mode:  unixMode(zf.Mode()),
			Size:  int64(min(zf.UncompressedSize64, 1<<62)),
		}, rc)
		if err = errors.Join(err, rc.Close()); err != nil {
			return err
		}
	}
	return nil
}

// tar walks a tar stream; config marks package config paths (DEB conffiles).
func (w *walker) tar(chain []string, r io.Reader, config map[string]bool, dirs bool) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := clean(hdr.Name)
		if name == "" {
			continue
		}
		f := core.File{
			Chain:  appendChain(chain, name),
			Mode:   uint32(hdr.Mode) & 0o7777,
			User:   owner(hdr.Uname, hdr.Uid),
			Group:  owner(hdr.Gname, hdr.Gid),
			Size:   hdr.Size,
			Config: config["/"+name],
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			f.Mode |= modeReg
			if err := w.entry(f, tr); err != nil {
				return err
			}
		case tar.TypeDir:
			if dirs {
				f.Mode |= modeDir
				w.files = append(w.files, f)
			}
		case tar.TypeSymlink:
			f.Mode |= modeLink
			f.Link = hdr.Linkname
			w.files = append(w.files, f)
		}
	}
}

// owner names a tar entry's user or group; archives written without names keep only ids.
func owner(name string, id int) string {
	switch {
	case name != "":
		return name
	case id == 0:
		return "root"
	}
	return strconv.Itoa(id)
}

func appendChain(chain []string, name string) []string {
	out := make([]string, len(chain), len(chain)+1)
	copy(out, chain)
	return append(out, name)
}

func clean(name string) string {
	name = strings.TrimPrefix(name, "./")
	return strings.TrimSuffix(strings.TrimPrefix(name, "/"), "/")
}

func unixMode(m fs.FileMode) uint32 {
	u := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		u |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		u |= 0o2000
	}
	switch {
	case m.IsDir():
		u |= modeDir
	case m&fs.ModeSymlink != 0:
		u |= modeLink
	default:
		u |= modeReg
	}
	return u
}

func zipType(name string) string {
	if ext := strings.ToLower(path.Ext(name)); ext != "" {
		return ext[1:]
	}
	return "zip"
}

var versioned = regexp.MustCompile(`^(.+?)[-_]v?(\d[\w.+~-]*)$`)

// nameVersion splits "app-1.2.3.war" into ("app", "1.2.3").
func nameVersion(base string) (string, string) {
	stem := base
	for _, suffix := range tarballSuffixes {
		if strings.HasSuffix(strings.ToLower(base), suffix) {
			stem = base[:len(base)-len(suffix)]
			break
		}
	}
	if stem == base {
		stem = strings.TrimSuffix(base, path.Ext(base))
	}
	if m := versioned.FindStringSubmatch(stem); m != nil {
		return m[1], m[2]
	}
	return stem, ""
}
