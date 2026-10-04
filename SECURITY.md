# Security policy

The latest released version of packdiff is supported. Please update before reporting an issue.

Report security vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/jmurray2011/packdiff/security/advisories/new). Include the version, platform, reproduction steps and impact, with fictional or redacted evidence. Expect acknowledgement within five business days; coordinated disclosure timing is agreed during investigation.

packdiff reads artifacts it does not control. The scope includes archive and payload parsing (RPM, DEB, zip, tar, cpio, class files, source maps), extraction to disk, memory and depth limits, secret redaction, and the integrity of the JSON and HTML output. A crafted artifact that crashes packdiff, exhausts memory past the documented limits, writes outside the extraction directory, or leaks a redacted value is in scope. Issues in embedded Syft should also be reported privately to that project.

Known advisory: [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) affects golang.org/x/crypto/openpgp in a required module. packdiff does not import or call that package; govulncheck reports it as unreachable. No fix is available for that advisory. Recheck reachability and upstream status when dependencies change.
