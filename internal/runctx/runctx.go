// File: internal/runctx/runctx.go (complete file)

package runctx

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Context struct {
	RunID        string
	StartedAtUTC time.Time
	OutputDir    string
}

func New(baseDir string) (*Context, error) {
	now := time.Now().UTC()
	runID := now.Format("20060102_150405")
	outDir := filepath.Join(baseDir, fmt.Sprintf("run_%s", runID))

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	return &Context{
		RunID:        runID,
		StartedAtUTC: now,
		OutputDir:    outDir,
	}, nil
}
