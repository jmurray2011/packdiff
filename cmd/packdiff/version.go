// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime/debug"
	"strings"
)

// versionDetails returns the version and the --version line. A stamped buildVersion wins;
// an unstamped build installed with go install reports its module version.
func versionDetails(linked string, info *debug.BuildInfo) (string, string) {
	version := linked
	if version == "dev" && info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = strings.TrimPrefix(info.Main.Version, "v")
	}
	line := "packdiff " + version
	if info != nil {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				line += " commit " + s.Value
				break
			}
		}
		if info.GoVersion != "" {
			line += " " + info.GoVersion
		}
	}
	return version, line
}
