// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/rpmpack"

	"github.com/jmurray2011/packdiff/core"
)

var update = flag.Bool("update", false, "rewrite golden files")

// class builds a class file whose constant pool holds strs as CONSTANT_Utf8 entries.
func class(strs ...string) []byte {
	var b bytes.Buffer
	w := func(v any) { _ = binary.Write(&b, binary.BigEndian, v) }
	w(uint32(0xCAFEBABE))
	w(uint32(61))
	w(uint16(len(strs) + 1))
	for _, s := range strs {
		w(uint8(1))
		w(uint16(len(s)))
		b.WriteString(s)
	}
	return b.Bytes()
}

func jar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range slices.Sorted(func(yield func(string) bool) {
		for k := range files {
			if !yield(k) {
				return
			}
		}
	}) {
		f, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(files[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type release struct {
	version, prein string
	requires       []string
	files          []rpmpack.RPMFile
}

func buildRPM(t *testing.T, dir string, r release) string {
	t.Helper()
	pkg, err := rpmpack.NewRPM(rpmpack.RPMMetaData{Name: "app", Version: r.version, Release: "1", Arch: "noarch", Compressor: "gzip"})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range r.requires {
		if err := pkg.Requires.Set(req); err != nil {
			t.Fatal(err)
		}
	}
	pkg.AddPrein(r.prein)
	for _, f := range r.files {
		if f.Owner == "" {
			f.Owner, f.Group = "root", "root"
		}
		if f.Mode == 0 {
			f.Mode = 0o100644
		}
		pkg.AddFile(f)
	}
	var buf bytes.Buffer
	if err := pkg.Write(&buf); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "app-"+r.version+"-1.noarch.rpm")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func geoJar(t *testing.T, version string) []byte {
	return jar(t, map[string]string{
		"META-INF/MANIFEST.MF":                          "Manifest-Version: 1.0\n",
		"META-INF/maven/org.example/geo/pom.properties": "groupId=org.example\nartifactId=geo\nversion=" + version + "\n",
	})
}

func releases(t *testing.T, dir string) (string, string) {
	classes := "/opt/app/webapp/WEB-INF/classes/"
	base := buildRPM(t, dir, release{
		version: "1.2.3", prein: "groupadd -r app\n", requires: []string{"java-11-headless"},
		files: []rpmpack.RPMFile{
			{Name: "/opt/app/conf/app.properties", Type: rpmpack.ConfigFile, Body: []byte("timeout=30\ndb.url=jdbc:postgresql://db.example.net:5432/app\n")},
			{Name: classes + "com/example/Geo.class", Body: class("https://old.example.net/api", "SHA-1", "${geo.retries:3}")},
			{Name: classes + "git.properties", Body: []byte("git.commit.id=aaa\n")},
			{Name: "/opt/app/webapp/WEB-INF/lib/geo-1.0.jar", Body: geoJar(t, "1.0")},
			{Name: "/opt/app/db/V1__init.sql", Body: []byte("create table accounts (id bigint primary key);\n")},
			{Name: "/opt/app/bin/run.sh", Mode: 0o100755, Body: []byte("#!/bin/sh\nexec java -jar app.jar\n")},
			{Name: "/usr/lib/app/libnative.so", Mode: 0o100755, Body: []byte("\x7fELF build 1")},
		},
	})
	head := buildRPM(t, dir, release{
		version: "1.2.4", prein: "groupadd -r app\nuseradd -r -g app app\n", requires: []string{"java-17-headless"},
		files: []rpmpack.RPMFile{
			{Name: "/opt/app/conf/app.properties", Type: rpmpack.ConfigFile, Body: []byte("timeout=60\ndb.url=jdbc:postgresql://db2.example.net:5432/app\n")},
			{Name: classes + "com/example/Geo.class", Body: class("https://api.example.net/v2/geocode", "SHA-256", "AES/GCM/NoPadding", "${geo.retries:5}")},
			{Name: classes + "git.properties", Body: []byte("git.commit.id=bbb\n")},
			{Name: "/opt/app/webapp/WEB-INF/lib/geo-1.1.jar", Body: geoJar(t, "1.1")},
			{Name: "/opt/app/db/V1__init.sql", Body: []byte("create table accounts (id bigint primary key);\n")},
			{Name: "/opt/app/db/V2__geo.sql", Body: []byte("create table geo_cache (id bigint);\nalter table accounts add column region text;\n")},
			{Name: "/opt/app/bin/run.sh", Mode: 0o104755, Body: []byte("#!/bin/sh\nexec java -jar app.jar\n")},
			{Name: "/usr/lib/app/libnative.so", Mode: 0o100755, Body: []byte("\x7fELF build 2")},
			{Name: "/usr/lib/systemd/system/app.service", Body: []byte("[Service]\nUser=app\nExecStart=/opt/app/bin/run.sh --port=8443\n")},
		},
	})
	return base, head
}

// golden compares got with testdata/golden/name after replacing the temp dir, or rewrites it.
func golden(t *testing.T, name, dir string, got []byte) {
	t.Helper()
	got = bytes.ReplaceAll(got, []byte(dir), []byte("<dir>"))
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil { //nolint:gosec // checked-in test data
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./cmd/packdiff -run RPM -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden; review the change and rerun with -update", name)
	}
}

func TestRPMEndToEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base, head := releases(t, dir)
	out, page := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.html")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--base", base, "--head", head, "--first-party", "com.example", "--out", out, "--html", page, "--format", "full"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r core.Result
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	subjects := map[string]bool{}
	for _, c := range r.Changes {
		subjects[string(c.Category)+" "+c.Subject] = true
		if len(c.Locations) == 0 {
			t.Errorf("no location: %s %s", c.Category, c.Subject)
		}
	}
	for _, want := range []string{
		"config opt/app/conf/app.properties#timeout",
		"config ${geo.retries}",
		"outbound https://api.example.net",
		"outbound https://old.example.net",
		"outbound jdbc:postgresql://db2.example.net:5432",
		"crypto alg:SHA-256",
		"crypto alg:AES/GCM/NoPadding",
		"schema opt/app/db/V2__geo.sql",
		"host script:preinstall",
		"host user:app",
		"host requires:java-17-headless",
		"host file:opt/app/bin/run.sh",
		"host unit:app.service#User",
		"host listen:8443",
		"deps org.example:geo",
		"files usr/lib/app/libnative.so",
	} {
		if !subjects[want] {
			t.Errorf("missing change %q", want)
		}
	}
	if !slices.ContainsFunc(r.Suppressed, func(c core.Change) bool { return strings.Contains(c.Subject, "git.properties#") }) {
		t.Error("git.properties change not suppressed")
	}

	golden(t, "rpm.json", dir, data)
	page2, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "rpm.html", dir, page2)
	golden(t, "rpm.txt", dir, stdout.Bytes())
}
