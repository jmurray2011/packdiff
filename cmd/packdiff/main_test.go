// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/jmurray2011/packdiff/core"
)

func tgz(t *testing.T, dir, name string, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
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
		if _, err := tw.Write([]byte(files[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := tgz(t, dir, "app-1.2.3.tar.gz", map[string]string{
		"app/conf/app.properties": "timeout=30\n",
		"app/db/V1__init.sql":     "create table a (id int);",
	})
	head := tgz(t, dir, "app-1.2.4.tar.gz", map[string]string{
		"app/conf/app.properties": "timeout=60\n",
		"app/db/V1__init.sql":     "create table a (id int);",
		"app/db/V2__geo.sql":      "create table geo (id int);",
	})
	out := filepath.Join(dir, "packdiff.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"--base", base, "--head", head, "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "app 1.2.3 -> 1.2.4 | config ~1 | outbound 0 | crypto 0 | schema +1 |") {
		t.Fatalf("stdout:\n%s", stdout.String())
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r core.Result
	if err := json.Unmarshal(first, &r); err != nil {
		t.Fatal(err)
	}
	if r.Head.Type != "tar.gz" || len(r.Head.SHA256) != 64 || r.Tool.Name != "packdiff" {
		t.Fatalf("result header = %+v %+v", r.Head, r.Tool)
	}
	for _, c := range r.Changes {
		if len(c.Locations) == 0 || len(c.Locations[0].Chain) < 2 {
			t.Fatalf("change without location chain: %+v", c)
		}
	}

	second := filepath.Join(dir, "again.json")
	if code := run([]string{"--base", base, "--head", head, "--out", second, "--format", "none"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	b, _ := os.ReadFile(second)
	if !bytes.Equal(first, b) {
		t.Fatal("identical inputs gave different JSON")
	}

	if code := run([]string{"--base", base, "--head", base, "--format", "none"}, &stdout, &stderr); code != 0 {
		t.Fatalf("identical artifacts exit = %d", code)
	}
}

func TestRunUsageErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	art := tgz(t, dir, "app-1.0.tar.gz", map[string]string{"a.properties": "a=1\n"})
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("- category: nope\n  subject: x\n  decision: accepted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"missing head":   {"--base", art},
		"removed option": {"--base", art, "--head", art, "--gate", "config"},
		"bad format":     {"--base", art, "--head", art, "--format", "fancy"},
		"missing file":   {"--base", art, "--head", filepath.Join(dir, "nope.rpm")},
		"unknown option": {"--base", art, "--head", art, "--frobnicate"},
		"bad rules":      {"--base", art, "--head", art, "--rules", bad},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
	}
}

func TestRunRules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := tgz(t, dir, "app-1.0.tar.gz", map[string]string{"app/a.properties": "endpoint=https://old.example.net\n"})
	head := tgz(t, dir, "app-1.1.tar.gz", map[string]string{"app/a.properties": "endpoint=https://new.example.net\n"})
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte("suppress:\n  - category: outbound\n    subject: 'example\\.net$'\n    reason: test hosts\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "r.json")
	var stdout, stderr bytes.Buffer
	run([]string{"--base", base, "--head", head, "--rules", rules, "--out", out, "--format", "none"}, &stdout, &stderr)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var r core.Result
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	outbound := r.Summary[core.Outbound]
	if len(r.Tool.RulesDigest) != 64 || outbound.Suppressed != 2 || outbound.Added+outbound.Removed != 0 {
		t.Fatalf("digest=%q outbound=%+v", r.Tool.RulesDigest, outbound)
	}
}

func TestRunHTML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := tgz(t, dir, "app-1.0.tar.gz", map[string]string{"app/a.properties": "timeout=30\n"})
	head := tgz(t, dir, "app-1.1.tar.gz", map[string]string{"app/a.properties": "timeout=60\n"})
	page := filepath.Join(dir, "report.html")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--base", base, "--head", head, "--html", page, "--format", "none"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("<!doctype html>")) || !bytes.Contains(data, []byte("timeout")) {
		t.Fatalf("report:\n%.300s", data)
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "packdiff ") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestVersionDetails(t *testing.T) {
	t.Parallel()
	info := &debug.BuildInfo{
		GoVersion: "go1.26.8", Main: debug.Module{Version: "v1.2.3"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}},
	}
	if v, line := versionDetails("dev", info); v != "1.2.3" || line != "packdiff 1.2.3 commit abc123 go1.26.8" {
		t.Fatalf("v=%q line=%q", v, line)
	}
	if v, _ := versionDetails("0.4.0", info); v != "0.4.0" {
		t.Fatalf("stamped version overridden: %q", v)
	}
}
