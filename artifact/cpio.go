// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	rpmutils "github.com/sassoftware/go-rpmutils"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// ErrPayload reports an RPM payload that cannot be read.
var ErrPayload = errors.New("bad rpm payload")

const (
	newcMagic     = "070701"
	strippedMagic = "07070X"
	newcHeaderLen = 110
)

// rpmPayload decompresses the payload that follows an RPM header.
func rpmPayload(r io.Reader, hdr *rpmutils.RpmHeader) (io.Reader, error) {
	if hdr.HasTag(rpmutils.PAYLOADFORMAT) {
		if f, err := hdr.GetString(rpmutils.PAYLOADFORMAT); err == nil && f != "cpio" {
			return nil, fmt.Errorf("%w: payload format %q", ErrUnsupported, f)
		}
	}
	comp := "gzip"
	if hdr.HasTag(rpmutils.PAYLOADCOMPRESSOR) {
		c, err := hdr.GetString(rpmutils.PAYLOADCOMPRESSOR)
		if err != nil {
			return nil, err
		}
		comp = c
	}
	switch comp {
	case "gzip":
		return gzip.NewReader(r)
	case "bzip2":
		return bzip2.NewReader(r), nil
	case "xz":
		return xz.NewReader(r)
	case "lzma":
		return lzma.NewReader(r)
	case "zstd":
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case "", "identity":
		return r, nil
	}
	return nil, fmt.Errorf("%w: payload compressor %q", ErrUnsupported, comp)
}

// counter tracks how many bytes have been read, for cpio's four-byte alignment.
type counter struct {
	r *bufio.Reader
	n int64
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *counter) skip(n int64) error {
	m, err := io.CopyN(io.Discard, c, n)
	if err == nil && m != n {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (c *counter) align() error { return c.skip((4 - c.n%4) % 4) }

// walkCpio reads a newc cpio archive as RPM writes it, including RPM's stripped entries
// ("07070X" plus an index into files), whose name and size come from the RPM header.
// visit gets each entry's metadata and content; hard-link entries without content are skipped.
func walkCpio(r io.Reader, files []rpmutils.FileInfo, visit func(rpmutils.FileInfo, io.Reader) error) error {
	byName := make(map[string]int, len(files))
	for i, fi := range files {
		byName[fi.Name()] = i
	}
	c := &counter{r: bufio.NewReaderSize(r, 64<<10)}
	magic := make([]byte, 6)
	for {
		if _, err := io.ReadFull(c, magic); err != nil {
			return fmt.Errorf("%w: entry header: %w", ErrPayload, err)
		}
		var fi rpmutils.FileInfo
		var size int64
		switch string(magic) {
		case strippedMagic:
			idx, err := hexField(c)
			if err != nil {
				return err
			}
			if idx < 0 || idx >= int64(len(files)) {
				return fmt.Errorf("%w: stripped entry index %d of %d files", ErrPayload, idx, len(files))
			}
			fi = files[idx]
			if t := fi.Mode() & 0o170000; t == modeReg || t == modeLink {
				size = fi.Size() // directories and other types carry no content
			}
		case newcMagic:
			var fields [13]int64
			for i := range fields {
				v, err := hexField(c)
				if err != nil {
					return err
				}
				fields[i] = v
			}
			var namesize int64
			size, namesize = fields[6], fields[11]
			if namesize < 1 || namesize > 4096 || size < 0 {
				return fmt.Errorf("%w: entry name size %d, file size %d", ErrPayload, namesize, size)
			}
			raw := make([]byte, namesize)
			if _, err := io.ReadFull(c, raw); err != nil {
				return fmt.Errorf("%w: entry name: %w", ErrPayload, err)
			}
			name := strings.TrimPrefix(strings.TrimSuffix(string(raw), "\x00"), ".")
			if name == "TRAILER!!!" {
				return nil
			}
			idx, ok := byName[name]
			if !ok {
				return fmt.Errorf("%w: archive entry %q is not in the header", ErrPayload, name)
			}
			fi = files[idx]
			// Directories can carry a header size (4096 from rpmpack-based tools) with no
			// content, so only regular files are checked: a hard link set stores content
			// once, on its last entry.
			if fi.Mode()&0o170000 == modeReg {
				switch {
				case size == 0 && fi.Size() > 0:
					fi = nil
				case size != fi.Size():
					return fmt.Errorf("%w: %s is %d bytes in the archive, %d in the header", ErrPayload, name, size, fi.Size())
				}
			}
		default:
			return fmt.Errorf("%w: bad magic %q", ErrPayload, magic)
		}
		if err := c.align(); err != nil {
			return fmt.Errorf("%w: %w", ErrPayload, err)
		}
		if err := visitEntry(c, fi, size, visit); err != nil {
			return err
		}
	}
}

// visitEntry hands size bytes of content to visit (unless fi is nil), then skips any
// unread content and the alignment padding.
func visitEntry(c *counter, fi rpmutils.FileInfo, size int64, visit func(rpmutils.FileInfo, io.Reader) error) error {
	start := c.n
	if fi != nil {
		if err := visit(fi, io.LimitReader(c, size)); err != nil {
			return err
		}
	}
	if err := c.skip(size - (c.n - start)); err != nil {
		return fmt.Errorf("%w: %w", ErrPayload, err)
	}
	if err := c.align(); err != nil {
		return fmt.Errorf("%w: %w", ErrPayload, err)
	}
	return nil
}

func hexField(r io.Reader) (int64, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, fmt.Errorf("%w: header field: %w", ErrPayload, err)
	}
	v, err := strconv.ParseInt(string(b), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: header field %q", ErrPayload, b)
	}
	return v, nil
}
