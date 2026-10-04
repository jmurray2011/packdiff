// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func tarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func compress(t *testing.T, kind string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	var err error
	switch kind {
	case "xz":
		w, err = xz.NewWriter(&buf)
	case "zst":
		w, err = zstd.NewWriter(&buf)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestOpenDEBCompressions(t *testing.T) {
	t.Parallel()
	control := tarBytes(t, map[string][]byte{
		"./control":   []byte("Package: app\nVersion: 2.0-1\nDepends: libc6\n"),
		"./preinst":   []byte("#!/bin/sh\naddgroup --system app\n"),
		"./conffiles": []byte("/etc/app/app.env\n"),
	})
	data := tarBytes(t, map[string][]byte{"./etc/app/app.env": []byte("A=1\n")})
	for _, c := range []struct{ control, data string }{{"xz", "zst"}, {"zst", "xz"}, {"", ""}} {
		members := [][2]string{{"debian-binary", "2.0\n"}}
		ctl, dat := control, data
		ctlName, datName := "control.tar", "data.tar"
		if c.control != "" {
			ctl, ctlName = compress(t, c.control, control), ctlName+"."+c.control
		}
		if c.data != "" {
			dat, datName = compress(t, c.data, data), datName+"."+c.data
		}
		members = append(members, [2]string{ctlName, string(ctl)}, [2]string{datName, string(dat)})
		s, err := Open(context.Background(), writeFile(t, "app_2.0-1_all.deb", arArchive(members)), Options{Want: wantProps})
		if err != nil {
			t.Fatalf("%s/%s: %v", ctlName, datName, err)
		}
		if s.Artifact.Name != "app" || !strings.Contains(s.Package.Scripts["preinstall"], "addgroup") || !slices.Equal(s.Package.Requires, []string{"libc6"}) {
			t.Errorf("%s/%s: control not read: %+v %+v", ctlName, datName, s.Artifact, s.Package)
		}
		if f := byKey(s)["etc/app/app.env"]; !f.Config || f.SHA256 == "" {
			t.Errorf("%s/%s: data not read: %+v", ctlName, datName, f)
		}
	}
}

func TestTarNumericOwners(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "./etc/app.conf", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg},                       // uid/gid 0, no names
		{Name: "./var/lib/app/db", Mode: 0o600, Size: 1, Uid: 105, Gid: 108, Typeflag: tar.TypeReg}, // service account, no names
		{Name: "./opt/app/x", Mode: 0o644, Size: 1, Uname: "app", Gname: "app", Uid: 999, Gid: 999, Typeflag: tar.TypeReg},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), writeFile(t, "app-1.0.tar", buf.Bytes()), Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	files := byKey(s)
	for k, want := range map[string]string{"etc/app.conf": "root:root", "var/lib/app/db": "105:108", "opt/app/x": "app:app"} {
		if got := files[k].User + ":" + files[k].Group; got != want {
			t.Errorf("%s owner = %q, want %q", k, got, want)
		}
	}
}
