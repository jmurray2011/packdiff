// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jmurray2011/packdiff/core"
)

var (
	unitSettings = regexp.MustCompile(`^(Exec\w+|User|Group|SupplementaryGroups|DynamicUser|After|Before|Wants|Requires|BindsTo|PartOf|Type|UMask|Listen\w+|Protect\w+|Private\w+|Restrict\w+|NoNewPrivileges|CapabilityBoundingSet|AmbientCapabilities|ReadWritePaths|ReadOnlyPaths|InaccessiblePaths|SystemCall\w+|LockPersonality|MemoryDenyWriteExecute)$`)
	portArg      = regexp.MustCompile(`(?:--server\.port|--port|-Dserver\.port)[= ](\d+)`)
	portDefault  = regexp.MustCompile(`^\$\{[^:}]+:(\d+)\}$`)
	scriptSplit  = regexp.MustCompile(`\|\||&&|[;|&\n]`)
)

func hostChanges(base, head core.Snapshot) []core.Change {
	var out []core.Change
	out = append(out, diff(core.Host, scriptFacts(base), scriptFacts(head), scriptDiff)...)
	out = append(out, diff(core.Host, accountFacts(base), accountFacts(head), nil)...)
	out = append(out, diff(core.Host, relationFacts(base), relationFacts(head), nil)...)
	out = append(out, fileChanges(base, head)...)
	out = append(out, diff(core.Host, unitFacts(base), unitFacts(head), nil)...)
	out = append(out, diff(core.Host, portFacts(base), portFacts(head), nil)...)
	return out
}

func packageFile(s core.Snapshot) core.File {
	return core.File{Chain: []string{path.Base(s.Artifact.Path)}}
}

func scriptFacts(s core.Snapshot) facts {
	fs := facts{}
	for phase, body := range s.Package.Scripts {
		fs.add("script:"+phase, body, packageFile(s))
	}
	return fs
}

func scriptDiff(_ string, before, after fact) []string {
	return lineDiff(strings.Split(strings.TrimRight(before.value, "\n"), "\n"), strings.Split(strings.TrimRight(after.value, "\n"), "\n"))
}

// maxDiffCells caps the LCS table; past it the changed middle is shown as removed then added.
const maxDiffCells = 4 << 20

// lineDiff returns "- " and "+ " lines. Common leading and trailing lines are trimmed first,
// then the middle is aligned by longest common subsequence when the table stays small.
func lineDiff(a, b []string) []string {
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		a, b = a[1:], b[1:]
	}
	for len(a) > 0 && len(b) > 0 && a[len(a)-1] == b[len(b)-1] {
		a, b = a[:len(a)-1], b[:len(b)-1]
	}
	if (len(a)+1)*(len(b)+1) > maxDiffCells {
		out := make([]string, 0, len(a)+len(b))
		for _, l := range a {
			out = append(out, "- "+l)
		}
		for _, l := range b {
			out = append(out, "+ "+l)
		}
		return out
	}
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || lcs[i][j+1] >= lcs[i+1][j]):
			out = append(out, "+ "+b[j])
			j++
		default:
			out = append(out, "- "+a[i])
			i++
		}
	}
	return out
}

// accountFacts finds users and groups created by install scripts.
func accountFacts(s core.Snapshot) facts {
	fs := facts{}
	for phase, body := range s.Package.Scripts {
		for _, seg := range scriptSplit.Split(body, -1) {
			fields := strings.Fields(seg)
			if len(fields) < 2 {
				continue
			}
			var kind string
			switch path.Base(fields[0]) {
			case "useradd", "adduser":
				kind = "user"
			case "groupadd", "addgroup":
				kind = "group"
			default:
				continue
			}
			name := ""
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "-") {
					name = f
				}
			}
			if name == "" {
				continue
			}
			fs.add(kind+":"+name, phase, packageFile(s))
			if kind == "user" && slices.Contains(fields, "--group") {
				fs.add("group:"+name, phase, packageFile(s))
			}
		}
	}
	return fs
}

func relationFacts(s core.Snapshot) facts {
	fs := facts{}
	for _, r := range s.Package.Requires {
		fs.add("requires:"+r, "", packageFile(s))
	}
	for _, p := range s.Package.Provides {
		fs.add("provides:"+p, "", packageFile(s))
	}
	return fs
}

func attrs(f core.File) string {
	s := fmt.Sprintf("mode=%04o owner=%s:%s", f.Mode&0o7777, f.User, f.Group)
	if f.Config {
		s += " config"
	}
	if f.Caps != "" {
		s += " caps=" + f.Caps
	}
	if f.Link != "" {
		s += " link=" + f.Link
	}
	return s
}

// notable files are reported when added or removed; every payload file is compared for attributes.
func notable(f core.File) bool {
	name := f.Key()
	regular := f.Mode&0o170000 == 0o100000
	return (regular && f.Mode&0o111 != 0) || f.Mode&0o7000 != 0 || f.Caps != "" || f.Config ||
		strings.HasPrefix(name, "etc/") || isUnit(f.Name())
}

// fileChanges compares attributes of every payload file, but reports additions and
// removals only for notable files; ordinary application content is not host footprint.
func fileChanges(base, head core.Snapshot) []core.Change {
	collect := func(s core.Snapshot) (facts, map[string]core.File) {
		fs, files := facts{}, map[string]core.File{}
		for _, f := range s.Files {
			if payload(f) {
				fs.add("file:"+core.Unversioned(f.Chain), attrs(f), f)
				files["file:"+core.Unversioned(f.Chain)] = f
			}
		}
		return fs, files
	}
	bf, bfiles := collect(base)
	hf, hfiles := collect(head)
	var out []core.Change
	groups := map[[2]string][]core.Change{}
	for _, c := range diff(core.Host, bf, hf, modeDetails) {
		switch {
		case c.Kind == core.Added && !notable(hfiles[c.Subject]):
		case c.Kind == core.Removed && !notable(bfiles[c.Subject]):
		case c.Kind == core.Changed:
			k := [2]string{*c.Before, *c.After}
			groups[k] = append(groups[k], c)
		default:
			out = append(out, c)
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(groups), func(a, b [2]string) int {
		return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1])
	}) {
		cs := groups[k]
		if len(cs) <= groupThreshold {
			out = append(out, cs...)
			continue
		}
		g := core.Change{
			Category: core.Host, Kind: core.Changed, Subject: "files:" + k[0] + " -> " + k[1],
			Before: ptr(k[0]), After: ptr(k[1]),
		}
		g.Details = append(append(g.Details, cs[0].Details...), fmt.Sprintf("%d files", len(cs)))
		for _, c := range cs {
			g.Details = append(g.Details, strings.TrimPrefix(c.Subject, "file:"))
			g.Locations = append(g.Locations, c.Locations...)
		}
		out = append(out, g)
	}
	return out
}

// groupThreshold is how many files may share one attribute change before they are reported
// as a single change, as when a build's umask changes every file at once.
const groupThreshold = 20

func modeDetails(_ string, before, after fact) []string {
	var b, a uint32
	if _, err := fmt.Sscanf(before.value, "mode=%o", &b); err != nil {
		return nil
	}
	if _, err := fmt.Sscanf(after.value, "mode=%o", &a); err != nil {
		return nil
	}
	var out []string
	for _, bit := range []struct {
		mask uint32
		name string
	}{{0o4000, "setuid"}, {0o2000, "setgid"}, {0o0002, "world-writable"}} {
		switch {
		case a&bit.mask != 0 && b&bit.mask == 0:
			out = append(out, bit.name+" added")
		case a&bit.mask == 0 && b&bit.mask != 0:
			out = append(out, bit.name+" removed")
		}
	}
	return out
}

func unitFacts(s core.Snapshot) facts {
	fs := facts{}
	for _, f := range s.Files {
		if f.Content == nil || !isUnit(f.Name()) || f.InLibrary() {
			continue
		}
		vals := map[string][]string{}
		for _, kv := range unitKeys(string(f.Content)) {
			if unitSettings.MatchString(kv[0]) {
				vals[kv[0]] = append(vals[kv[0]], kv[1])
			}
		}
		for k, v := range vals {
			fs.add("unit:"+f.Name()+"#"+k, strings.Join(v, "\n"), f)
		}
	}
	return fs
}

// unitKeys returns Key=Value pairs from a systemd unit, in order.
func unitKeys(text string) [][2]string {
	var out [][2]string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out = append(out, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
		}
	}
	return out
}

// portFacts collects listening ports from server config, Tomcat server.xml, and unit arguments.
func portFacts(s core.Snapshot) facts {
	fs := facts{}
	for _, f := range s.Files {
		if f.Content == nil || f.InLibrary() {
			continue
		}
		where := core.Unversioned(f.Chain)
		if f.Name() == "server.xml" {
			for port, what := range tomcatPorts(f.Content) {
				fs.add("listen:"+port, where+" "+what, f)
			}
			continue
		}
		if isUnit(f.Name()) {
			for _, kv := range unitKeys(string(f.Content)) {
				if strings.HasPrefix(kv[0], "Exec") {
					for _, m := range portArg.FindAllStringSubmatch(kv[1], -1) {
						fs.add("listen:"+m[1], where+" "+kv[0], f)
					}
				}
			}
		}
		for k, v := range keyValues(f) {
			if k != "server.port" && !strings.HasSuffix(k, ".server.port") && k != "SERVER_PORT" {
				continue
			}
			if m := portDefault.FindStringSubmatch(v); m != nil {
				v = m[1]
			}
			if v != "" && strings.Trim(v, "0123456789") == "" {
				fs.add("listen:"+v, where+" "+k, f)
			}
		}
	}
	return fs
}

// tomcatPorts maps each port in server.xml to what opens it.
func tomcatPorts(data []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) || err != nil {
			return out
		}
		el, ok := tok.(xml.StartElement)
		if !ok || (el.Name.Local != "Connector" && el.Name.Local != "Server") {
			continue
		}
		var port, desc string
		desc = el.Name.Local
		for _, a := range el.Attr {
			switch a.Name.Local {
			case "port":
				port = a.Value
			case "protocol":
				desc += " protocol=" + a.Value
			case "SSLEnabled":
				if strings.EqualFold(a.Value, "true") {
					desc += " ssl"
				}
			}
		}
		if el.Name.Local == "Server" {
			desc += " shutdown"
		}
		if port != "" && port != "-1" {
			out[port] = desc
		}
	}
}
