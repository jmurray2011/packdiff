// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseNotes(t *testing.T) {
	text := "# Changelog\n\n## [Unreleased]\nfuture\n\n## [0.1.0-rc1] - 2099-01-01\nfictional candidate\n\n## [0.1.0] - 2099-01-02\nfictional stable\n"
	notes, err := releaseNotes(text, "v0.1.0-rc1")
	if err != nil || !strings.Contains(notes, "fictional candidate") || strings.Contains(notes, "fictional stable") {
		t.Fatal(notes, err)
	}
	for _, tag := range []string{"v1.0.0", "fictional", "v0.1.0;echo"} {
		if _, err := releaseNotes(text, tag); err == nil {
			t.Fatal(tag)
		}
	}
}

func TestBinarySBOM(t *testing.T) {
	dir := t.TempDir()
	for path, text := range map[string]string{"go.mod": "module fictional.invalid/testapp\n\ngo 1.26.8\n", "main.go": "package main\nfunc main(){}\n"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "fictional.exe")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, b)
	}
	data, err := binarySBOM(context.Background(), binary)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BomFormat  string
		Components []struct{ Name string }
	}
	if err = json.Unmarshal(data, &doc); err != nil || doc.BomFormat != "CycloneDX" || len(doc.Components) == 0 {
		t.Fatalf("SBOM: %s %v", data, err)
	}
}
