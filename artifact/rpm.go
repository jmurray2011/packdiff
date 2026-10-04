// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"io"
	"slices"
	"strings"

	rpmutils "github.com/sassoftware/go-rpmutils"

	"github.com/jmurray2011/packdiff/core"
)

// Script tags absent from go-rpmutils' constants.
const (
	tagPretrans  = 1151
	tagPosttrans = 1152
)

var rpmScripts = []struct {
	tag   int
	phase string
}{
	{tagPretrans, "pretrans"},
	{rpmutils.PREIN, "preinstall"},
	{rpmutils.POSTIN, "postinstall"},
	{rpmutils.PREUN, "preuninstall"},
	{rpmutils.POSTUN, "postuninstall"},
	{tagPosttrans, "posttrans"},
}

func (w *walker) rpm(r io.Reader, base string, s *core.Snapshot) error {
	pkg, err := rpmutils.ReadRpm(r)
	if err != nil {
		return err
	}
	hdr := pkg.Header
	nevra, err := hdr.GetNEVRA()
	if err != nil {
		return err
	}
	s.Artifact.Name = nevra.Name
	s.Artifact.Version = nevra.Version + "-" + nevra.Release
	if nevra.Epoch != "" && nevra.Epoch != "0" {
		s.Artifact.Version = nevra.Epoch + ":" + s.Artifact.Version
	}

	s.Package.Scripts = map[string]string{}
	for _, sc := range rpmScripts {
		if hdr.HasTag(sc.tag) {
			if body, err := hdr.GetString(sc.tag); err == nil && body != "" {
				s.Package.Scripts[sc.phase] = body
			}
		}
	}
	s.Package.Requires = relations(hdr, rpmutils.REQUIRENAME)
	s.Package.Provides = relations(hdr, rpmutils.PROVIDENAME)

	infos, err := hdr.GetFiles()
	if err != nil {
		return err
	}
	caps := map[string]string{}
	if hdr.HasTag(rpmutils.FILECAPS) {
		vals, err := hdr.GetStrings(rpmutils.FILECAPS)
		if err != nil {
			return err
		}
		for i, fi := range infos {
			if i < len(vals) && vals[i] != "" {
				caps[fi.Name()] = vals[i]
			}
		}
	}

	payload, err := rpmPayload(r, hdr)
	if err != nil {
		return err
	}
	return walkCpio(payload, infos, func(fi rpmutils.FileInfo, body io.Reader) error {
		f := core.File{
			Chain:  []string{base, clean(fi.Name())},
			Mode:   uint32(fi.Mode()),
			User:   fi.UserName(),
			Group:  fi.GroupName(),
			Size:   fi.Size(),
			Config: fi.Flags()&rpmutils.RPMFILE_CONFIG != 0,
			Caps:   caps[fi.Name()],
		}
		switch f.Mode & 0o170000 {
		case modeReg:
			return w.entry(f, body)
		case modeLink:
			f.Link = fi.Linkname()
			w.files = append(w.files, f)
		case modeDir:
			w.files = append(w.files, f)
		}
		return nil
	})
}

// relations returns sorted, de-duplicated dependency names, minus rpmlib() markers.
func relations(hdr *rpmutils.RpmHeader, tag int) []string {
	if !hdr.HasTag(tag) {
		return []string{}
	}
	names, err := hdr.GetStrings(tag)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !strings.HasPrefix(n, "rpmlib(") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
