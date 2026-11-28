package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kuasar-sandbox/connector/pkg/egress"
	"github.com/spf13/cobra"
)

// A status report describes one saved observation, not the health or ownership
// of a live process. Keep native counters as raw JSON to avoid losing precision.
type egressStatusReport struct {
	Path       string          `json:"path"`
	UpdatedAt  time.Time       `json:"updated_at"`
	AgeSeconds float64         `json:"age_seconds"`
	Snapshot   json.RawMessage `json:"snapshot"`
}

func newEgressStatusCommand() *cobra.Command {
	var config, runtimeDir string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Read the saved Egress snapshot and its age (not a health probe)",
		Long: "Read status.json without contacting or signalling the gateway. " +
			"The output includes the file modification time and age; a retained or copied file does not prove liveness. " +
			"Use --runtime-dir when the configuration being edited is invalid.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := runtimeDir
			if config != "" {
				cfg, err := egress.LoadConfig(config)
				if err != nil {
					return fmt.Errorf("load gateway configuration (use --runtime-dir to inspect the previous snapshot): %w", err)
				}
				dir = cfg.RuntimeDir
			}
			if dir == "" {
				return fmt.Errorf("provide a nonempty --config or --runtime-dir")
			}
			report, err := readEgressStatus(dir, time.Now())
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		},
	}
	cmd.Flags().StringVar(&config, "config", "", "Gateway JSON/YAML configuration used to locate runtime_dir")
	cmd.Flags().StringVar(&runtimeDir, "runtime-dir", "", "Read this directory's status.json without loading configuration")
	cmd.MarkFlagsOneRequired("config", "runtime-dir")
	cmd.MarkFlagsMutuallyExclusive("config", "runtime-dir")
	return cmd
}

func readEgressStatus(runtimeDir string, now time.Time) (egressStatusReport, error) {
	var report egressStatusReport
	path, err := filepath.Abs(filepath.Join(runtimeDir, "status.json"))
	if err != nil {
		return report, err
	}
	// Do not block while opening a FIFO or device accidentally left at the
	// snapshot path. The descriptor is checked before any bytes are read.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return report, fmt.Errorf("open Egress snapshot: %w", err)
	}
	defer file.Close()
	// Stat and read the same open inode even if the gateway replaces the path.
	info, err := file.Stat()
	if err != nil {
		return report, fmt.Errorf("stat Egress snapshot: %w", err)
	}
	if !info.Mode().IsRegular() {
		return report, fmt.Errorf("Egress snapshot %s is not a regular file", path)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return report, fmt.Errorf("read Egress snapshot: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return report, fmt.Errorf("decode Egress snapshot: %w", err)
	}
	if object == nil {
		return report, fmt.Errorf("Egress snapshot must be a JSON object")
	}
	return egressStatusReport{
		Path: path, UpdatedAt: info.ModTime().UTC(),
		AgeSeconds: now.Sub(info.ModTime()).Seconds(), Snapshot: raw,
	}, nil
}
