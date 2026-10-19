package health

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type learningFakeProvider struct {
	*fakeProvider
	status *LearningStatus
}

func (f learningFakeProvider) LearningStatus() *LearningStatus { return f.status }

func TestBuildCarriesLearningStatus(t *testing.T) {
	plain := Build(&fakeProvider{}, "v", nil)
	if plain.AntispamLearning != nil {
		t.Fatal("a provider without a learner reported learning")
	}
	pending := 0
	want := &LearningStatus{LastPass: time.Unix(100, 0).UTC(), PendingReports: &pending, LiveClusters: 3}
	snap := Build(learningFakeProvider{&fakeProvider{}, want}, "v", nil)
	want.LiveClusters = 9
	if snap.AntispamLearning == nil || snap.AntispamLearning.LiveClusters != 3 || *snap.AntispamLearning.PendingReports != 0 {
		t.Fatalf("learning = %+v", snap.AntispamLearning)
	}
	data, err := json.Marshal(snap)
	if err != nil || !strings.Contains(string(data), `"antispam_learning":{`) || !strings.Contains(string(data), `"pending_reports":0`) {
		t.Fatalf("snapshot: %s, %v", data, err)
	}
}

func TestUnenumeratedNotReportedAsZeroPending(t *testing.T) {
	snap := Build(learningFakeProvider{&fakeProvider{}, &LearningStatus{PassUnfinished: true}}, "v", nil)
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"pending_reports"`) {
		t.Fatalf("unenumerated folders reported a pending count: %s", data)
	}
}
