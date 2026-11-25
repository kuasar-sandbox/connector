package egress

import "testing"

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
