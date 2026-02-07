// File: internal/logging/logging.go (complete file)

package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Setup creates a logger and sets it as the process-wide default.
// This keeps the CLI usage simple while allowing packages to rely on slog.Default().
func Setup(level string) {
	slog.SetDefault(New(level))
}

func New(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}
