// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/rpmpack"

	"github.com/jmurray2011/packdiff/core"
)

func zipBytes(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		f, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGz(t testing.TB, files map[string][]byte, mode int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: mode, Size: int64(len(files[n])), Uname: "root", Gname: "root", Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func jar(t testing.TB) []byte {
	return zipBytes(t, map[string][]byte{
		"com/example/Geo.class":                         []byte("\xca\xfe\xba\xbe"),
		"META-INF/maven/org.example/geo/pom.properties": []byte("groupId=org.example\nartifactId=geo\nversion=1.0\n"),
	})
}

func writeFile(t testing.TB, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func rpmFile(t testing.TB) string {
	t.Helper()
	r, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "app", Version: "1.2.3", Release: "1", Arch: "noarch", Compressor: "gzip"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Requires.Set("java-17-headless"); err != nil {
		t.Fatal(err)
	}
	war := zipBytes(t, map[string][]byte{
		"WEB-INF/lib/geo-1.0.jar":                jar(t),
		"WEB-INF/classes/application.properties": []byte("server.port=8080\n"),
	})
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app/conf/app.properties", Body: []byte("timeout=30\n"), Mode: 0o100640, Owner: "app", Group: "app", Type: rpmpack.ConfigFile})
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app/app.war", Body: war, Mode: 0o100644, Owner: "root", Group: "root"})
	r.AddFile(rpmpack.RPMFile{Name: "/opt/app/bin/run.sh", Body: []byte("#!/bin/sh\n"), Mode: 0o104755, Owner: "root", Group: "root"})
	r.AddPrein("groupadd -r app")
	var buf bytes.Buffer
	if err := r.Write(&buf); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "app-1.2.3-1.noarch.rpm", buf.Bytes())
}

// arArchive writes a minimal ar(1) archive as used by .deb.
func arArchive(members [][2]string) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m[0], 0, 0, 0, "100644", len(m[1]))
		buf.WriteString(m[1])
		if len(m[1])%2 == 1 {
			buf.WriteString("\n")
		}
	}
	return buf.Bytes()
}

func debFile(t *testing.T) string {
	t.Helper()
	control := tarGz(t, map[string][]byte{
		"./control":   []byte("Package: app\nVersion: 1.2.3-1\nDepends: openjdk-17-jre-headless, adduser (>= 3.0)\nProvides: app-api\n"),
		"./postinst":  []byte("#!/bin/sh\nadduser --system app\n"),
		"./conffiles": []byte("/etc/app/app.env\n"),
	}, 0o755)
	data := tarGz(t, map[string][]byte{
		"./etc/app/app.env":     []byte("APP_MODE=prod\n"),
		"./opt/app/lib/geo.jar": jar(t),
	}, 0o644)
	deb := arArchive([][2]string{
		{"debian-binary", "2.0\n"},
		{"control.tar.gz", string(control)},
		{"data.tar.gz", string(data)},
	})
	return writeFile(t, "app_1.2.3-1_all.deb", deb)
}

func byKey(s core.Snapshot) map[string]core.File {
	m := map[string]core.File{}
	for _, f := range s.Files {
		m[f.Key()] = f
	}
	return m
}

func wantProps(chain []string) bool { return strings.HasSuffix(chain[len(chain)-1], ".properties") }

func TestOpenRPM(t *testing.T) {
	t.Parallel()
	s, err := Open(context.Background(), rpmFile(t), Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	a := s.Artifact
	if a.Type != "rpm" || a.Name != "app" || a.Version != "1.2.3-1" || len(a.SHA256) != 64 {
		t.Fatalf("artifact = %+v", a)
	}
	if !strings.Contains(s.Package.Scripts["preinstall"], "groupadd -r app") {
		t.Fatalf("scripts = %v", s.Package.Scripts)
	}
	if !slices.Contains(s.Package.Requires, "java-17-headless") {
		t.Fatalf("requires = %v", s.Package.Requires)
	}

	files := byKey(s)
	conf := files["opt/app/conf/app.properties"]
	if !conf.Config || conf.User != "app" || conf.Mode&0o777 != 0o640 || string(conf.Content) != "timeout=30\n" {
		t.Fatalf("config file = %+v", conf)
	}
	if run := files["opt/app/bin/run.sh"]; run.Mode&0o4000 == 0 || run.Content != nil {
		t.Fatalf("setuid script = %+v", run)
	}

	cls, ok := files["opt/app/app.war!WEB-INF/lib/geo-1.0.jar!com/example/Geo.class"]
	if !ok {
		t.Fatalf("nested class missing; keys: %v", slices.Sorted(func(yield func(string) bool) {
			for k := range files {
				if !yield(k) {
					return
				}
			}
		}))
	}
	want := []string{"app-1.2.3-1.noarch.rpm", "opt/app/app.war", "WEB-INF/lib/geo-1.0.jar", "com/example/Geo.class"}
	if !slices.Equal(cls.Chain, want) || !cls.InLibrary() {
		t.Fatalf("chain = %v", cls.Chain)
	}
	if p := files["opt/app/app.war!WEB-INF/classes/application.properties"]; string(p.Content) != "server.port=8080\n" || p.InLibrary() {
		t.Fatalf("war properties = %+v", p)
	}
}

func TestOpenDEB(t *testing.T) {
	t.Parallel()
	s, err := Open(context.Background(), debFile(t), Options{Want: func([]string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Artifact.Type != "deb" || s.Artifact.Name != "app" || s.Artifact.Version != "1.2.3-1" {
		t.Fatalf("artifact = %+v", s.Artifact)
	}
	if !strings.Contains(s.Package.Scripts["postinstall"], "adduser --system app") {
		t.Fatalf("scripts = %v", s.Package.Scripts)
	}
	if !slices.Equal(s.Package.Requires, []string{"adduser", "openjdk-17-jre-headless"}) {
		t.Fatalf("requires = %v", s.Package.Requires)
	}
	files := byKey(s)
	if env := files["etc/app/app.env"]; !env.Config || string(env.Content) != "APP_MODE=prod\n" {
		t.Fatalf("conffile = %+v", env)
	}
	if _, ok := files["opt/app/lib/geo.jar!META-INF/maven/org.example/geo/pom.properties"]; !ok {
		t.Fatal("jar inside deb not walked")
	}
}

func TestOpenPlainArchives(t *testing.T) {
	t.Parallel()
	tgz := writeFile(t, "app-1.2.3.tar.gz", tarGz(t, map[string][]byte{"app/conf/app.properties": []byte("a=1\n")}, 0o644))
	s, err := Open(context.Background(), tgz, Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	if s.Artifact.Type != "tar.gz" || string(byKey(s)["app/conf/app.properties"].Content) != "a=1\n" {
		t.Fatalf("tar.gz snapshot = %+v", s)
	}

	war := writeFile(t, "app-1.2.3.war", zipBytes(t, map[string][]byte{"WEB-INF/lib/geo-1.0.jar": jar(t)}))
	s, err = Open(context.Background(), war, Options{Want: wantProps})
	if err != nil {
		t.Fatal(err)
	}
	if s.Artifact.Type != "war" || s.Artifact.Name != "app" || s.Artifact.Version != "1.2.3" {
		t.Fatalf("war artifact = %+v", s.Artifact)
	}
	if _, ok := byKey(s)["WEB-INF/lib/geo-1.0.jar!com/example/Geo.class"]; !ok {
		t.Fatal("jar inside war not walked")
	}
}

func TestOpenRejectsUnknown(t *testing.T) {
	t.Parallel()
	_, err := Open(context.Background(), writeFile(t, "notes.txt", []byte("hello")), Options{Want: wantProps})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenExtractsPayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := Open(context.Background(), rpmFile(t), Options{Want: wantProps, ExtractTo: dir}); err != nil {
		t.Fatal(err)
	}
	war, err := os.ReadFile(filepath.Join(dir, "opt/app/app.war"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(war), int64(len(war))); err != nil {
		t.Fatalf("extracted war unreadable: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "opt/app/conf/app.properties")); err != nil || string(b) != "timeout=30\n" {
		t.Fatalf("extracted config = %q, %v", b, err)
	}
}

func TestOpenRefusesTraversal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	evil := writeFile(t, "evil-1.0.tar.gz", tarGz(t, map[string][]byte{"../../escape.txt": []byte("x")}, 0o644))
	_, err := Open(context.Background(), evil, Options{Want: wantProps, ExtractTo: filepath.Join(dir, "out")})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("file written outside extraction root")
	}
}
