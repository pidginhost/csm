package daemon

import (
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
)

// phpRelayMetrics holds every series the module emits via the local
// internal/metrics OpenMetrics implementation.
//
// Defined as a struct of pointers so callers can pass nil and skip
// observation. All increments at call sites are guarded by
// `if e.metrics != nil` checks.
type phpRelayMetrics struct {
	Findings               *metrics.CounterVec // labels: path
	Actions                *metrics.CounterVec // labels: action, result
	PathSkipped            *metrics.CounterVec // labels: path, reason
	WindowsActive          *metrics.GaugeVec   // labels: kind (script/ip/account)
	MsgIDIndexSize         *metrics.GaugeVec   // labels: layer (memory/bbolt)
	MsgindexPersistDropped *metrics.Counter
	MsgindexPersistErrors  *metrics.Counter
	InotifyOverflows       *metrics.Counter
	SpoolReadErrors        *metrics.Counter
	UserdataErrors         *metrics.Counter
	ActiveMsgsCapped       *metrics.Counter
	SpoolScanFallbacks     *metrics.CounterVec // labels: reason
	ActionGone             *metrics.Counter
}

var (
	phpRelayMetricsOnce     sync.Once
	phpRelayMetricsInstance *phpRelayMetrics
)

// newPHPRelayMetrics constructs (and registers via the package default
// registry) the singleton metric set. Subsequent calls return the same
// instance -- sync.Once protects against the duplicate-name panic from
// metrics.MustRegister.
func newPHPRelayMetrics() *phpRelayMetrics {
	phpRelayMetricsOnce.Do(func() {
		m := &phpRelayMetrics{
			Findings:               metrics.NewCounterVec("csm_php_relay_findings_total", "Findings emitted by php_relay paths.", []string{"path"}),
			Actions:                metrics.NewCounterVec("csm_php_relay_actions_total", "AutoFreeze actions attempted.", []string{"action", "result"}),
			PathSkipped:            metrics.NewCounterVec("csm_php_relay_path_skipped_total", "Path evaluation skipped.", []string{"path", "reason"}),
			WindowsActive:          metrics.NewGaugeVec("csm_php_relay_windows_active", "Active windows per kind.", []string{"kind"}),
			MsgIDIndexSize:         metrics.NewGaugeVec("csm_php_relay_msgid_index_size", "msgIDIndex size by storage layer.", []string{"layer"}),
			MsgindexPersistDropped: metrics.NewCounter("csm_php_relay_msgindex_persist_dropped_total", "Persist queue overflow drops."),
			MsgindexPersistErrors:  metrics.NewCounter("csm_php_relay_msgindex_persist_errors_total", "bbolt commit failures."),
			InotifyOverflows:       metrics.NewCounter("csm_php_relay_inotify_overflows_total", "IN_Q_OVERFLOW events."),
			SpoolReadErrors:        metrics.NewCounter("csm_php_relay_spool_read_errors_total", "Spool -H read errors."),
			UserdataErrors:         metrics.NewCounter("csm_php_relay_userdata_errors_total", "cpanelUserDomains read errors."),
			ActiveMsgsCapped:       metrics.NewCounter("csm_php_relay_active_msgs_capped_total", "scriptState.activeMsgs cap-hit events."),
			SpoolScanFallbacks:     metrics.NewCounterVec("csm_php_relay_spool_scan_fallbacks_total", "AutoFreeze spool-scan fallback invocations.", []string{"reason"}),
			ActionGone:             metrics.NewCounter("csm_php_relay_action_gone_total", "Messages already absent at exim -Mf time."),
		}
		metrics.MustRegister("csm_php_relay_findings_total", m.Findings)
		metrics.MustRegister("csm_php_relay_actions_total", m.Actions)
		metrics.MustRegister("csm_php_relay_path_skipped_total", m.PathSkipped)
		metrics.MustRegister("csm_php_relay_windows_active", m.WindowsActive)
		metrics.MustRegister("csm_php_relay_msgid_index_size", m.MsgIDIndexSize)
		metrics.MustRegister("csm_php_relay_msgindex_persist_dropped_total", m.MsgindexPersistDropped)
		metrics.MustRegister("csm_php_relay_msgindex_persist_errors_total", m.MsgindexPersistErrors)
		metrics.MustRegister("csm_php_relay_inotify_overflows_total", m.InotifyOverflows)
		metrics.MustRegister("csm_php_relay_spool_read_errors_total", m.SpoolReadErrors)
		metrics.MustRegister("csm_php_relay_userdata_errors_total", m.UserdataErrors)
		metrics.MustRegister("csm_php_relay_active_msgs_capped_total", m.ActiveMsgsCapped)
		metrics.MustRegister("csm_php_relay_spool_scan_fallbacks_total", m.SpoolScanFallbacks)
		metrics.MustRegister("csm_php_relay_action_gone_total", m.ActionGone)
		phpRelayMetricsInstance = m
	})
	return phpRelayMetricsInstance
}
