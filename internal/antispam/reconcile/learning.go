package reconcile

import (
	"sync"

	"github.com/pidginhost/csm/internal/antispam"
)

// LearningState remembers a learning configuration whose apply failed the
// learning check, so learning stays off instead of reloading rspamd with the
// same failing configuration every pass (spec 6.1).
type LearningState struct {
	mu sync.Mutex
	// generation is the held learning configuration; empty holds nothing.
	generation string
	// roundcube is the learning configuration whose webmail include did not
	// take effect, and why.
	roundcube, roundcubeWhy string
	// paused is the Redis memory guard's last state.
	paused bool
}

func (st *LearningState) setRedisPaused(paused bool) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.paused = paused
}

func (st *LearningState) redisPaused() bool {
	if st == nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.paused
}

// NewLearningState returns empty learning memory.
func NewLearningState() *LearningState { return &LearningState{} }

func (st *LearningState) hold(generation string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.generation = generation
}

// held reports whether generation is held; any other generation lifts the
// hold.
func (st *LearningState) held(generation string) bool {
	if st == nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.generation != generation {
		st.generation = ""
		return false
	}
	return generation != ""
}

func (st *LearningState) holdRoundcube(generation, why string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.roundcube, st.roundcubeWhy = generation, why
}

// roundcubeHeld returns why the include is held for generation; any other
// generation lifts the hold.
func (st *LearningState) roundcubeHeld(generation string) (string, bool) {
	if st == nil {
		return "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.roundcube != generation || generation == "" {
		st.roundcube, st.roundcubeWhy = "", ""
		return "", false
	}
	return st.roundcubeWhy, true
}

// learningGeneration identifies the desired learning configuration: the
// rendered learning files when their keys are loaded, else the directory
// they come from.
func learningGeneration(s antispam.Settings) string {
	if !s.Learning {
		return ""
	}
	if files, err := antispam.RenderLearning(s); err == nil {
		return antispam.Generation(files)
	}
	return "dir:" + s.LearningDir
}

// applyLearningHold turns learning off while its configuration is held.
func (st *LearningState) applyLearningHold(s antispam.Settings) (antispam.Settings, []antispam.Problem) {
	if !st.held(learningGeneration(s)) {
		return s, nil
	}
	s.Learning, s.Roundcube = false, false
	return s, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonApplyFailed,
		Detail: "rspamd did not load CSM's learning configuration as written; learning stays off until its configuration changes or CSM restarts"}}
}

// applyRoundcubeHold turns the webmail include off while it is held.
func (st *LearningState) applyRoundcubeHold(s antispam.Settings) (antispam.Settings, []antispam.Problem) {
	why, held := st.roundcubeHeld(learningGeneration(s))
	if !held || !s.Roundcube {
		return s, nil
	}
	s.Roundcube = false
	return s, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning, Key: antispam.ReasonRoundcube,
		Detail: why + "; the webmail Junk-button include stays off until the learning configuration changes or CSM restarts"}}
}
