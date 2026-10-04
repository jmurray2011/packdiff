// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLicenseElections(t *testing.T) {
	for _, tc := range []struct{ path, text, want string }{{"github.com/spdx/tools-golang", "fictional dual text", "Apache-2.0"}, {"github.com/cyphar/filepath-securejoin", "fictional dual text", "BSD-3-Clause"}, {"fictional.invalid/lib", "Mozilla Public License, v. 2.0", "MPL-2.0"}, {"fictional.invalid/lib", "Permission is hereby granted, free of charge", "MIT"}} {
		got, err := electLicense(tc.path, tc.text)
		if err != nil || got != tc.want {
			t.Fatalf("%s %v", got, err)
		}
	}
	if _, err := electLicense("fictional.invalid/unknown", "fictional unknown"); err == nil {
		t.Fatal("unknown license accepted")
	}
}

func TestNoticesPreserveAllTexts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, text := range map[string]string{"LICENSE": "Permission is hereby granted, free of charge\nfictional license\n", "NOTICE": "fictional Apache notice\n", "nested/COPYING.extra": "fictional secondary text\n"} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	text, err := moduleNotice("fictional.invalid/lib", "v1.0.0", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fictional.invalid/lib", "v1.0.0", "Elected license: MIT", "fictional Apache notice\n", "fictional secondary text\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestMPLSourceURL(t *testing.T) {
	for _, tc := range []struct{ path, version, want string }{{"github.com/fictional/lib/v2", "v2.0.1", "https://github.com/fictional/lib/tree/v2.0.1"}, {"github.com/fictional/lib", "v1.2.2-0.20990101010101-abcdef123456", "https://github.com/fictional/lib/tree/abcdef123456"}} {
		if got := moduleSourceURL(tc.path, tc.version); got != tc.want {
			t.Fatal(got)
		}
	}
}
