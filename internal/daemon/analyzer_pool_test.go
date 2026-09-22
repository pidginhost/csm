//go:build linux

package daemon

import "testing"

// The analyzer pool never dropped below four workers. On a one or two core
// host that is four content scans competing with the periodic checks and with
// whatever the machine is actually serving.

func TestAnalyzerWorkerCountFollowsTheCoreCount(t *testing.T) {
	for _, tc := range []struct {
		cpus int
		want int
	}{
		{0, minAnalyzerWorkers},
		{1, minAnalyzerWorkers},
		{2, 2},
		{4, 4},
		{16, maxAnalyzerWorkers},
		{64, maxAnalyzerWorkers},
	} {
		if got := analyzerWorkerCount(tc.cpus); got != tc.want {
			t.Errorf("analyzerWorkerCount(%d) = %d, want %d", tc.cpus, got, tc.want)
		}
	}
}
