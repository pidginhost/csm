package ipmap

import "time"

// CanaryGrace is how long rspamd may take to load a new map before the
// canary counts against it (spec 8.4).
const CanaryGrace = 5 * time.Minute

// CanaryProblem judges the writer's state and one canary answer: seen is
// the generation rspamd reported ("" when CSM_IP_CANARY was absent). It
// returns what is wrong, or "".
func CanaryProblem(st State, seen string, probeErr error, now time.Time) string {
	if st.Err != nil {
		return "CSM could not write the IP map (" + st.Err.Error() + "); rspamd keeps using the previous map"
	}
	if st.Gen == "" || seen == st.Gen || now.Sub(st.WrittenAt) < CanaryGrace {
		return ""
	}
	if probeErr != nil {
		return "CSM could not ask rspamd which IP map it uses: " + probeErr.Error()
	}
	if seen == "" {
		return "rspamd is not using the current CSM IP map: its canary answer carries no CSM_IP_CANARY; check the CSM_IP rule and that rspamd can read the map file"
	}
	return "rspamd is not using the current CSM IP map: it still reports generation " + seen + "; check that rspamd can read the map file"
}
