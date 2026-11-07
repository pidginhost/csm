package webui

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/redisinfo"
)

// A Redis that could not be asked must not read as an idle Redis: each figure
// is null when its probe failed and a real number, zero included, when it
// answered. Memory and keyspace are separate probes and fail independently.
func TestSampleMetricsRedisFiguresNullOnlyWhenProbeFails(t *testing.T) {
	probeErr := errors.New("dial tcp 127.0.0.1:6379: connection refused")
	t.Cleanup(func() {
		redisinfo.SetMemoryUsageForTest(nil)
		redisinfo.SetKeyspaceStatsForTest(nil)
	})

	for _, tc := range []struct {
		name     string
		memErr   error
		keysErr  error
		wantJSON []string
		wantMem  *uint64
		wantMax  *uint64
		wantKeys *int64
	}{
		{
			name:     "unreachable",
			memErr:   probeErr,
			keysErr:  probeErr,
			wantJSON: []string{`"redis_mem_mb":null`, `"redis_maxmem_mb":null`, `"redis_keys":null`},
		},
		{
			name:     "idle with no limit",
			wantJSON: []string{`"redis_mem_mb":3`, `"redis_maxmem_mb":0`, `"redis_keys":0`},
			wantMem:  ptrTo[uint64](3),
			wantMax:  ptrTo[uint64](0),
			wantKeys: ptrTo[int64](0),
		},
		{
			name:     "keyspace probe failed",
			keysErr:  probeErr,
			wantJSON: []string{`"redis_mem_mb":3`, `"redis_maxmem_mb":0`, `"redis_keys":null`},
			wantMem:  ptrTo[uint64](3),
			wantMax:  ptrTo[uint64](0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redisinfo.SetMemoryUsageForTest(func(context.Context) (uint64, uint64, error) {
				if tc.memErr != nil {
					return 0, 0, tc.memErr
				}
				return 3 * 1024 * 1024, 0, nil
			})
			redisinfo.SetKeyspaceStatsForTest(func(context.Context) (redisinfo.KeyspaceStat, error) {
				return redisinfo.KeyspaceStat{}, tc.keysErr
			})

			m := sampleMetrics()
			checkPtr(t, "RedisMemMB", m.RedisMemMB, tc.wantMem)
			checkPtr(t, "RedisMaxMB", m.RedisMaxMB, tc.wantMax)
			checkPtr(t, "RedisKeys", m.RedisKeys, tc.wantKeys)

			b, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			for _, want := range tc.wantJSON {
				if !strings.Contains(string(b), want) {
					t.Errorf("metrics JSON missing %s; got %s", want, b)
				}
			}
		})
	}
}

func ptrTo[T any](v T) *T { return &v }

func checkPtr[T comparable](t *testing.T, name string, got, want *T) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s = %v, want nil", name, *got)
	case want != nil && got == nil:
		t.Errorf("%s = nil, want %v", name, *want)
	case want != nil && *got != *want:
		t.Errorf("%s = %v, want %v", name, *got, *want)
	}
}
