package antispam

import (
	"errors"
	"testing"
)

func TestWorkerRedisCheckRejectsCurrentMailServiceUID(t *testing.T) {
	for _, uid := range []int{testRspamdUID, testRedisUID} {
		f := postfixLearningFacts()
		f.Dovecot.UIDs = []int{uid}
		if err := CheckLearningRedis(postfixLearningSettings(), f); err == nil {
			t.Fatalf("worker accepted mail stored as service uid %d", uid)
		}
	}
}

func TestPostfixAccountReadFailureKeepsInstalledLearning(t *testing.T) {
	f, s := postfixLearningFacts(), postfixLearningSettings()
	installLearningFor(t, &f, s)
	f.AccountNamesErr = errors.New("passwd unavailable")
	f.RspamdUIDErr = f.AccountNamesErr
	f.Redis.Err = f.AccountNamesErr
	f.Redis.GroupMembers = nil
	resolved, gate, problems := ResolveLearning(s, f)
	if !resolved.Learning || !gate.Install || gate.Publish || len(problems) != 1 || problems[0].Key != ReasonBackendUnavailable {
		t.Fatalf("account read failure removed learning: gate %+v, problems %+v", gate, problems)
	}
}
