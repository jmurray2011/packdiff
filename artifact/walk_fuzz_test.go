// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	rpmutils "github.com/sassoftware/go-rpmutils"

	"github.com/jmurray2011/packdiff/core"
)

// FuzzWalk feeds arbitrary bytes to every artifact reader with small limits. Errors are
// expected; panics and runaway memory are not.
func FuzzWalk(f *testing.F) {
	f.Add(zipBytes(f, map[string][]byte{"a.properties": []byte("a=1\n"), "lib/x.jar": zipBytes(f, map[string][]byte{"b": []byte("b")})}))
	f.Add(tarGz(f, map[string][]byte{"etc/app.env": []byte("A=1\n")}, 0o644))
	f.Add(arArchive([][2]string{{"debian-binary", "2.0\n"}, {"control.tar.gz", string(tarGz(f, map[string][]byte{"./control": []byte("Package: a\n")}, 0o644))}}))
	f.Add([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 1})
	lim := limits{depth: 3, nested: 1 << 20, live: 4 << 20, keep: 64 << 10, kept: 1 << 20}
	all := func([]string) bool { return true }
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		for _, walk := range []func(w *walker) error{
			func(w *walker) error { return w.rpm(bytes.NewReader(data), "a.rpm", &core.Snapshot{}) },
			func(w *walker) error { return w.deb(bytes.NewReader(data), "a.deb", &core.Snapshot{}) },
			func(w *walker) error { return w.zip([]string{"a.zip"}, bytes.NewReader(data), int64(len(data))) },
			func(w *walker) error { return w.tar([]string{"a.tar"}, bytes.NewReader(data), nil, true) },
		} {
			_ = walk(&walker{ctx: ctx, want: all, lim: lim})
		}
	})
}

// FuzzCpio feeds arbitrary bytes to the RPM payload reader with a real header's file table.
func FuzzCpio(f *testing.F) {
	data, err := os.ReadFile(rpmFile(f))
	if err != nil {
		f.Fatal(err)
	}
	hdr, err := rpmutils.ReadHeader(bytes.NewReader(data))
	if err != nil {
		f.Fatal(err)
	}
	infos, err := hdr.GetFiles()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("07070X00000000\x00\x0007070100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b00000000TRAILER!!!\x00"))
	f.Add([]byte("070701"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = walkCpio(bytes.NewReader(payload), infos, func(_ rpmutils.FileInfo, r io.Reader) error {
			_, err := io.Copy(io.Discard, r)
			return err
		})
	})
}
