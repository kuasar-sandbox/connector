package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCommittedPolicySurvivesRestartAndExplicitConfigWins(t *testing.T) {
	c := validConfig()
	c.RuntimeDir = t.TempDir()
	identity, err := policyIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	replacement := validConfig().Areas
	replacement[0].ACL = nil
	if err = persistPolicy(c.RuntimeDir, identity, replacement); err != nil {
		t.Fatal(err)
	}
	if err = restorePolicy(&c, identity); err != nil {
		t.Fatal(err)
	}
	if len(c.Areas[0].ACL) != 0 {
		t.Fatal("revoked ACL was resurrected on restart")
	}
	changed := validConfig()
	changed.RuntimeDir = c.RuntimeDir
	changed.MaxConnections = 8192
	newIdentity, _ := policyIdentity(changed)
	if err = restorePolicy(&changed, newIdentity); err != nil {
		t.Fatal(err)
	}
	if len(changed.Areas[0].ACL) != 1 {
		t.Fatal("explicit deployment configuration did not select its new baseline")
	}
}

func TestAllAcceptedAreaUpdatesRestoreBeyondRequestLimit(t *testing.T) {
	c := validConfig()
	c.RuntimeDir = t.TempDir()
	first := c.Areas[0]
	c.Areas = nil
	for i := 0; i < 16; i++ {
		area := first
		area.VNI += uint32(i)
		c.Areas = append(c.Areas, area)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	identity, err := policyIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	var currentArea uint32
	runner := &recordingRunner{reply: func(command string) (string, error) {
		if strings.HasPrefix(command, "egress-policy begin area ") {
			_, err := fmt.Sscanf(command, "egress-policy begin area %d", &currentArea)
			return "", err
		}
		if command == "egress-policy commit" {
			return fmt.Sprintf(`{"area":%d}`, currentArea), nil
		}
		return "", nil
	}}
	engine, err := NewEngine(c, runner)
	if err != nil {
		t.Fatal(err)
	}
	engine.persist = func(areas []Area) error { return persistPolicy(c.RuntimeDir, identity, areas) }
	for _, area := range c.Areas {
		area.ACL = make([]ACL, 4096)
		for i := range area.ACL {
			area.ACL[i] = first.ACL[0]
		}
		raw, err := json.Marshal(area)
		if err != nil {
			t.Fatal(err)
		}
		var request Area
		if err := Decode(strings.NewReader(string(raw)), &request); err != nil {
			t.Fatal(err)
		}
		if err := engine.ApplyArea(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := os.ReadFile(filepath.Join(c.RuntimeDir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot) <= 4<<20 {
		t.Fatal("fixture does not exceed the public request limit")
	}
	var request storedPolicy
	if err := Decode(strings.NewReader(string(snapshot)), &request); err == nil {
		t.Fatal("public request limit was relaxed")
	}
	if err := restorePolicy(&c, identity); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Areas, engine.config.Areas) {
		t.Fatal("accepted policy changed during restoration")
	}
}
