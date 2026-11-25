package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type storedPolicy struct {
	Configuration string `json:"configuration"`
	Areas         []Area `json:"areas"`
}

func policyIdentity(c Config) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}
func restorePolicy(c *Config, identity string) error {
	f, err := os.Open(filepath.Join(c.RuntimeDir, "policy.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var saved storedPolicy
	if err = Decode(f, &saved); err != nil {
		return err
	}
	// An explicit change to the deployment file selects a new desired baseline.
	if saved.Configuration != identity {
		return nil
	}
	original := c.Areas
	c.Areas = saved.Areas
	if err = c.Validate(); err != nil {
		c.Areas = original
		return err
	}
	return nil
}
func persistPolicy(dir, identity string, areas []Area) error {
	body, err := json.Marshal(storedPolicy{Configuration: identity, Areas: areas})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".policy-")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(path, filepath.Join(dir, "policy.json")); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
