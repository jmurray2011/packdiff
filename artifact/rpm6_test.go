// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/rpmpack"
	rpmutils "github.com/sassoftware/go-rpmutils"
)

// pad4 returns the zero bytes that align n to four.
func pad4(n int) []byte { return make([]byte, (4-n%4)%4) }

// stripPayload rewrites an RPM's newc cpio payload into the stripped form RPM 6 writes:
// each entry is "07070X" plus the file's index in the header, padded to four bytes, then
// the content padded to four. Name and size come from the header.
func stripPayload(t *testing.T, rpm []byte) []byte {
	t.Helper()
	hdr, err := rpmutils.ReadHeader(bytes.NewReader(rpm))
	if err != nil {
		t.Fatal(err)
	}
	infos, err := hdr.GetFiles()
	if err != nil {
		t.Fatal(err)
	}
	index := map[string]int{}
	for i, fi := range infos {
		index[fi.Name()] = i
	}
	end := hdr.GetRange().End
	gz, err := gzip.NewReader(bytes.NewReader(rpm[end:]))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for pos := 0; ; {
		h := payload[pos : pos+110]
		size, _ := strconv.ParseInt(string(h[54:62]), 16, 64)
		namesize, _ := strconv.ParseInt(string(h[94:102]), 16, 64)
		name := string(payload[pos+110 : pos+110+int(namesize)-1])
		body := pos + 110 + int(namesize)
		body += len(pad4(body))
		if name == "TRAILER!!!" {
			out.Write(payload[pos:]) // trailer stays a newc entry, as in RPM 6
			break
		}
		idx, ok := index[strings.TrimPrefix(name, ".")] // "./opt/x" or "/opt/x" in the archive
		if !ok {
			t.Fatalf("archive entry %q not in header", name)
		}
		e := fmt.Sprintf("07070X%08x", idx)
		out.WriteString(e)
		out.Write(pad4(len(e)))
		out.Write(payload[body : body+int(size)])
		out.Write(pad4(int(size)))
		pos = body + int(size)
		pos += len(pad4(pos))
	}

	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, rpm[:end]...), z.Bytes()...)
}

func TestOpenRPMStrippedPayload(t *testing.T) {
	t.Parallel()
	classic := rpmFile(t)
	data, err := os.ReadFile(classic)
	if err != nil {
		t.Fatal(err)
	}
	stripped := writeFile(t, "app-1.2.3-1.noarch.rpm", stripPayload(t, data))

	want, err := Open(context.Background(), classic, Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(context.Background(), stripped, Options{Want: wantProps})
	if err != nil {
		t.Fatalf("stripped payload: %v", err)
	}
	wf, gf := byKey(want), byKey(got)
	if len(gf) != len(wf) {
		t.Fatalf("files: got %d want %d", len(gf), len(wf))
	}
	for k, w := range wf {
		g := gf[k]
		if g.SHA256 != w.SHA256 || g.Mode != w.Mode || g.User != w.User || g.Config != w.Config || !bytes.Equal(g.Content, w.Content) {
			t.Errorf("%s: got %+v want %+v", k, g, w)
		}
	}
}

// rpmWithTree builds an RPM whose directory is recorded with a nonzero header size, as
// rpmpack and the tools built on it (nFPM, GoReleaser) write.
func rpmWithTree(t *testing.T) []byte {
	t.Helper()
	r, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "app", Version: "1.0", Release: "1", Arch: "noarch", Compressor: "gzip"})
	if err != nil {
		t.Fatal(err)
	}
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app", Mode: 0o40755, Owner: "root", Group: "root"})
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app/app.properties", Body: []byte("a=1\n"), Mode: 0o100644, Owner: "root", Group: "root"})
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app/current", Body: []byte("app.properties"), Mode: 0o120777, Owner: "root", Group: "root"})
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenRPMDirectoriesWithHeaderSize(t *testing.T) {
	t.Parallel()
	classic := rpmWithTree(t)
	for name, data := range map[string][]byte{"app-1.0-1.noarch.rpm": classic, "app-1.0-1.rpm6.rpm": stripPayload(t, classic)} {
		s, err := Open(context.Background(), writeFile(t, name, data), Options{Want: wantProps})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files := byKey(s)
		if d, ok := files["opt/app"]; !ok || d.Mode&0o170000 != modeDir {
			t.Errorf("%s: directory missing or wrong type: %+v", name, d)
		}
		if l, ok := files["opt/app/current"]; !ok || l.Mode&0o170000 != modeLink || l.Link != "app.properties" {
			t.Errorf("%s: symlink missing or wrong: %+v", name, l)
		}
		if f := files["opt/app/app.properties"]; string(f.Content) != "a=1\n" {
			t.Errorf("%s: file content = %q", name, f.Content)
		}
	}
}
