// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/jmurray2011/packdiff/core"
)

var debScripts = map[string]string{
	"preinst":  "preinstall",
	"postinst": "postinstall",
	"prerm":    "preuninstall",
	"postrm":   "postuninstall",
}

func (w *walker) deb(r io.Reader, base string, s *core.Snapshot) error {
	br := bufio.NewReader(r)
	if _, err := io.ReadFull(br, make([]byte, 8)); err != nil {
		return err
	}
	s.Package.Scripts = map[string]string{}
	conffiles := map[string]bool{}
	for {
		name, size, err := arHeader(br)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		body := io.LimitReader(br, size)
		switch {
		case strings.HasPrefix(name, "control.tar"):
			if err := w.debControl(name, body, s, conffiles); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		case strings.HasPrefix(name, "data.tar"):
			dr, err := decompress(name, body)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := w.tar([]string{base}, dr, conffiles, true); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			return err
		}
		if size%2 == 1 {
			if _, err := br.Discard(1); err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		}
	}
}

// arHeader reads one 60-byte ar member header.
func arHeader(r io.Reader) (string, int64, error) {
	h := make([]byte, 60)
	if _, err := io.ReadFull(r, h); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return "", 0, fmt.Errorf("truncated ar header: %w", err)
		}
		return "", 0, err
	}
	if string(h[58:60]) != "`\n" {
		return "", 0, errors.New("bad ar member header")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
	if err != nil || size < 0 {
		return "", 0, fmt.Errorf("bad ar member size: %q", h[48:58])
	}
	return strings.TrimSuffix(strings.TrimSpace(string(h[:16])), "/"), size, nil
}

// decompress opens a tar stream named by file suffix or tarball type: gz, xz, zst, bz2, or plain.
func decompress(name string, r io.Reader) (io.Reader, error) {
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".gz"), strings.HasSuffix(name, ".tgz"):
		return gzip.NewReader(r)
	case strings.HasSuffix(name, ".xz"), strings.HasSuffix(name, ".txz"):
		return xz.NewReader(r)
	case strings.HasSuffix(name, ".zst"), strings.HasSuffix(name, ".tzst"):
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case strings.HasSuffix(name, ".bz2"), strings.HasSuffix(name, ".tbz2"):
		return bzip2.NewReader(r), nil
	case strings.HasSuffix(name, "tar"):
		return r, nil
	}
	return nil, fmt.Errorf("%w: compression of %s", ErrUnsupported, name)
}

func (w *walker) debControl(name string, r io.Reader, s *core.Snapshot, conffiles map[string]bool) error {
	dr, err := decompress(name, r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		member := clean(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || hdr.Size > w.lim.keep {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		switch {
		case member == "control":
			fields := controlFields(body)
			s.Artifact.Name = fields["Package"]
			s.Artifact.Version = fields["Version"]
			s.Package.Requires = depNames(fields["Pre-Depends"] + "," + fields["Depends"])
			s.Package.Provides = depNames(fields["Provides"])
		case member == "conffiles":
			for _, line := range strings.Split(string(body), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					conffiles[line] = true
				}
			}
		case debScripts[member] != "":
			s.Package.Scripts[debScripts[member]] = string(body)
		}
	}
}

func controlFields(body []byte) map[string]string {
	out := map[string]string{}
	var last string
	for _, line := range strings.Split(string(bytes.TrimSpace(body)), "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if last != "" {
				out[last] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok {
			last = strings.TrimSpace(k)
			out[last] = strings.TrimSpace(v)
		}
	}
	return out
}

// depNames flattens a Depends-style list to sorted package names without versions or arch.
func depNames(list string) []string {
	out := []string{}
	for _, dep := range strings.Split(list, ",") {
		for _, alt := range strings.Split(dep, "|") {
			n, _, _ := strings.Cut(strings.TrimSpace(alt), " ")
			n, _, _ = strings.Cut(n, "(")
			n, _, _ = strings.Cut(n, ":")
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
