// File: internal/version/version.go (complete file)

package version

// These values are intended to be set at build time using -ldflags.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)
