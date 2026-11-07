package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/pidginhost/csm/internal/mcp"
	"github.com/pidginhost/csm/internal/redisinfo"
)

// A Redis that could not be asked must not read as an idle Redis: each figure
// is null when its probe failed and a real number, zero included, when it
// answered. Memory and keyspace are separate probes and fail independently.
func TestPerformanceRedisFiguresNullOnlyWhenProbeFails(t *testing.T) {
	probeErr := errors.New("Redis probe failed")
	const mb = 1024 * 1024
	t.Cleanup(func() {
		redisinfo.SetMemoryUsageForTest(nil)
		redisinfo.SetKeyspaceStatsForTest(nil)
	})

	for _, tc := range []struct {
		name      string
		used, max uint64
		keys      int64
		memErr    error
		keysErr   error
		want      [3]string
	}{
		{
			name:    "unreachable",
			memErr:  probeErr,
			keysErr: probeErr,
			want:    [3]string{"null", "null", "null"},
		},
		{
			name: "idle with no limit",
			used: 3 * mb,
			want: [3]string{"3", "0", "0"},
		},
		{
			name: "zero measurements",
			want: [3]string{"0", "0", "0"},
		},
		{
			name: "populated with a limit",
			used: 3 * mb,
			max:  16 * mb,
			keys: 9,
			want: [3]string{"3", "16", "9"},
		},
		{
			name:   "memory probe failed",
			memErr: probeErr,
			keys:   9,
			want:   [3]string{"null", "null", "9"},
		},
		{
			name:    "keyspace probe failed",
			used:    3 * mb,
			keysErr: probeErr,
			want:    [3]string{"3", "0", "null"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redisinfo.SetMemoryUsageForTest(func(context.Context) (uint64, uint64, error) {
				return tc.used, tc.max, tc.memErr
			})
			redisinfo.SetKeyspaceStatsForTest(func(context.Context) (redisinfo.KeyspaceStat, error) {
				return redisinfo.KeyspaceStat{TotalKeys: tc.keys}, tc.keysErr
			})

			assertMetrics := func(body []byte) {
				t.Helper()
				var response struct {
					Metrics map[string]json.RawMessage `json:"metrics"`
				}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatalf("decode performance response: %v", err)
				}
				for i, key := range []string{"redis_mem_mb", "redis_maxmem_mb", "redis_keys"} {
					if got := string(response.Metrics[key]); got != tc.want[i] {
						t.Errorf("%s = %q, want %q", key, got, tc.want[i])
					}
				}
			}
			s := newMCPTestServer(t)
			s.SetMCP(mcp.New(mcp.Options{Dispatcher: s.ReadOnly()}))
			const peer = "203.0.113.10:4000"
			w := mcpRequest(s, http.MethodGet, "/api/v1/performance", webTestToken, peer, "")
			if w.Code != http.StatusOK {
				t.Fatalf("performance API: status %d", w.Code)
			}
			assertMetrics(w.Body.Bytes())

			w = mcpRequest(s, http.MethodPost, "/mcp", mcpTestToken, peer,
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"csm_performance"}}`)
			if w.Code != http.StatusOK {
				t.Fatalf("performance MCP: status %d", w.Code)
			}
			var reply map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatalf("decode MCP response: %v", err)
			}
			text, isError := mcpResultText(t, reply)
			if isError {
				t.Fatalf("performance MCP: %s", text)
			}
			assertMetrics([]byte(text))
		})
	}
}
