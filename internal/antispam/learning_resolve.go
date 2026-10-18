package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// CodeLearning is the problem code of every learning finding (spec 10).
const CodeLearning = "learning"

// Learning reason keys. Plans B and C add the learner's own.
const (
	ReasonUnsupported        = "unsupported"
	ReasonUnsafe             = "unsafe_prerequisite"
	ReasonStateMismatch      = "state_mismatch"
	ReasonConfigConflict     = "config_conflict"
	ReasonApplyFailed        = "apply_failed"
	ReasonBackendUnavailable = "backend_unavailable"
	ReasonWorkerAbsent       = "worker_absent"
	ReasonRedisCapacity      = "redis_capacity"
	ReasonRedisPersistence   = "redis_persistence"
	ReasonRoundcube          = "roundcube_unavailable"
	ReasonRemovalIncomplete  = "removal_incomplete"
)

// LearningGate says what learning may do this pass. Install: CSM's learning
// files may be installed. Publish: the worker and Redis can take new
// hashes. Roundcube: the Junk-button include may be installed.
type LearningGate struct {
	Install   bool
	Publish   bool
	Roundcube bool
}

// stockFuzzyRule is the public rule rspamd ships; CSM's override replaces it
// on purpose (spec 6.1).
const stockFuzzyRule = "rspamd.com"

var (
	learningRspamdVersion = regexp.MustCompile(`^4\.2\.\d+$`)
	learningRedisVersion  = regexp.MustCompile(`^(5\.0|6\.2)\.\d+$`)
)

// learningCheck collects learning problems, one per reason, in the order
// found.
type learningCheck struct {
	problems []Problem
	seen     map[string]bool
}

func (c *learningCheck) add(reason, detail string) {
	if c.seen[reason] {
		return
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[reason] = true
	c.problems = append(c.problems, Problem{Code: CodeLearning, Severity: Warning, Key: reason, Detail: detail})
}

func (c *learningCheck) has(reasons ...string) bool {
	for _, r := range reasons {
		if c.seen[r] {
			return true
		}
	}
	return false
}

// ResolveLearning decides from host facts what learning may do. A definite
// failure (unsupported version, isolation, key state, configuration
// conflict) turns learning off so the pass reconciles core alone. A
// temporary probe failure keeps whatever is installed and stops new
// publications. Warnings keep learning on.
func ResolveLearning(s Settings, f HostFacts) (Settings, LearningGate, []Problem) {
	if !s.Learning {
		s.Roundcube = false
		return s, LearningGate{}, nil
	}
	var c learningCheck
	installed := learningInstalled(f)
	if f.LearningKeysErr != nil {
		c.add(ReasonStateMismatch, "the learning keys are missing or invalid; CSM never replaces part of a key set")
	}
	checkLearningVersions(&c, f)
	checkLearningController(&c, f)
	checkLearningRedis(&c, f)
	checkLearningLogs(&c, f)
	checkLearningConflicts(&c, s, f)
	if f.FuzzyListenErr != nil {
		c.add(ReasonBackendUnavailable, "CSM cannot read the UDP socket table to find the fuzzy worker")
	} else if f.FuzzyListenForeign {
		c.add(ReasonUnsafe, "a process of another user listens on the fuzzy worker's port 11335")
	}

	gate := LearningGate{}
	switch {
	case c.has(ReasonStateMismatch, ReasonUnsupported, ReasonUnsafe, ReasonConfigConflict):
	case c.has(ReasonBackendUnavailable):
		gate.Install = installed
	default:
		gate.Install, gate.Publish = true, true
	}
	if gate.Install && gate.Publish {
		if installed && !f.FuzzyListening {
			c.add(ReasonWorkerAbsent, "the fuzzy worker is not listening on 127.0.0.1:11335; restart rspamd")
			gate.Publish = false
		}
	}
	if gate.Install && gate.Publish && RedisGuard(f.Redis.Used, f.Redis.MaxMemory, f.RedisGuardPaused) {
		c.add(ReasonRedisCapacity, "Redis is at the learning memory guard; new hashes wait until usage falls below 70%")
		gate.Publish = false
	}
	if gate.Install {
		gate.Roundcube = roundcubeUsable(&c, f)
	}
	s.Learning, s.Roundcube = gate.Install, gate.Roundcube
	return s, gate, c.problems
}

// RedisGuard reports whether new publications pause: at 75% of maxmemory,
// staying paused until usage falls below 70%. No limit always pauses.
func RedisGuard(used, max uint64, paused bool) bool {
	if max == 0 {
		return true
	}
	// Compare against the ceiling of the threshold, without overflowing
	// uint64 or rounding away a byte near the boundary.
	numerator, denominator := uint64(3), uint64(4)
	if paused {
		numerator, denominator = 7, 10
	}
	limit := max/denominator*numerator + (max%denominator*numerator+denominator-1)/denominator
	return used >= limit
}

// learningInstalled reports whether CSM's learning worker file is on the
// host, the file whose presence makes CSM's scoring active.
func learningInstalled(f HostFacts) bool {
	for _, t := range f.Targets {
		if t.Path == LearningWorkerPath {
			return !t.Missing && t.Err == nil && ManagedFor(t.Kind, t.Content)
		}
	}
	return false
}

func checkLearningVersions(c *learningCheck, f HostFacts) {
	if f.RspamdVersion.Err != nil {
		c.add(ReasonBackendUnavailable, "rspamd's version is unknown")
	} else if v, _, err := ParseRspamdVersion(f.RspamdVersion.Stdout); err != nil {
		c.add(ReasonBackendUnavailable, "rspamd's version is unknown")
	} else if !learningRspamdVersion.MatchString(v) {
		c.add(ReasonUnsupported, "learning is qualified on rspamd 4.2 only")
	}
	if f.Redis.Version == "" && f.Redis.Err == nil && f.Redis.Unix {
		c.add(ReasonBackendUnavailable, "Redis's version is unknown")
	} else if f.Redis.Version != "" && !learningRedisVersion.MatchString(f.Redis.Version) {
		c.add(ReasonUnsupported, "learning is qualified on Redis 5.0 and 6.2 only")
	}
}

// checkLearningController requires a clean controller (spec 9), one private
// Unix controller socket owned by rspamd with mode 0600, and a private
// rspamadm control socket.
func checkLearningController(c *learningCheck, f HostFacts) {
	// The control socket is independent of controller config discovery. A
	// failed controller probe must not mask a known unsafe control socket.
	checkLearningControlSocket(c, f)
	if f.ControllerUnverifiable != nil {
		c.add(ReasonUnsafe, "CSM cannot verify rspamd's controller configuration")
		return
	}
	if f.ControllerErr != nil {
		c.add(ReasonBackendUnavailable, "CSM cannot read rspamd's controller configuration")
	}
	host := f.ControllerHost
	if host.RspamdUID < 0 {
		c.add(ReasonBackendUnavailable, "rspamd's service user is unknown")
	}
	unknownSocket := false
	for _, l := range f.Controller.Listeners {
		if !l.Unix {
			if tcpExposure(f.Controller, host) != "" {
				c.add(ReasonUnsafe, "rspamd's controller is reachable by other users; see antispam_controller_open")
			}
			continue
		}
		if host.RspamdUID < 0 {
			continue
		}
		s, ok := host.Sockets[l.Path]
		if !ok || s.Err != nil || s.Missing {
			unknownSocket = true
			c.add(ReasonBackendUnavailable, "CSM cannot check rspamd's controller socket")
			continue
		}
		if unixExposure(l, host) != "" {
			c.add(ReasonUnsafe, "rspamd's controller is reachable by other users; see antispam_controller_open")
		}
	}
	private := len(privateControllerSockets(f))
	if private > 1 || private == 0 && !unknownSocket && f.ControllerErr == nil && host.RspamdUID >= 0 {
		c.add(ReasonUnsafe, "learning needs exactly one private controller socket owned by rspamd with mode 0600")
	}
}

func learningSocketProtected(l ControllerListener, s SocketFacts, host ControllerHostFacts) bool {
	if s.Socket.ExtACL || len(s.Parents) == 0 || !directSocketPath(l, s) {
		return false
	}
	for _, p := range s.Parents {
		if p.ExtACL || !p.Mode.IsDir() || p.UID != 0 && p.UID != host.RspamdUID {
			return false
		}
	}
	return unixExposure(l, host) == ""
}

func checkLearningControlSocket(c *learningCheck, f HostFacts) {
	host := f.ControllerHost
	// The control socket gets the same checks as the controller socket:
	// root or rspamd's, mode 0600, no ACL, protected directories.
	cs := f.ControlSocket
	switch {
	case cs.Err != nil || cs.Missing:
		c.add(ReasonBackendUnavailable, "CSM cannot check rspamd's control socket")
	case cs.Socket.Mode.Perm()&0o077 != 0, cs.Socket.ExtACL:
		c.add(ReasonUnsafe, "rspamd's control socket is not private to root and rspamd")
	case host.RspamdUID < 0:
		c.add(ReasonBackendUnavailable, "rspamd's service user is unknown")
	case cs.Socket.UID != 0 && cs.Socket.UID != host.RspamdUID,
		!learningSocketProtected(ControllerListener{Unix: true, Path: cs.Socket.Path}, cs, withSocket(host, cs.Socket.Path, cs)):
		c.add(ReasonUnsafe, "rspamd's control socket is not private to root and rspamd")
	}
}

// privateControllerSockets lists the controller's Unix sockets that only
// root and rspamd can use: owned by rspamd, mode 0600, behind protected
// directories (spec 9).
func privateControllerSockets(f HostFacts) []string {
	host := f.ControllerHost
	var out []string
	for _, l := range f.Controller.Listeners {
		if !l.Unix || host.RspamdUID < 0 {
			continue
		}
		s, ok := host.Sockets[l.Path]
		if ok && s.Err == nil && !s.Missing && s.Socket.UID == host.RspamdUID &&
			s.Socket.Mode.Perm() == 0o600 && learningSocketProtected(l, s, host) {
			out = append(out, l.Path)
		}
	}
	return out
}

// PrivateControllerSocket returns the one private controller socket learning
// talks to, or false when there is none or more than one.
func PrivateControllerSocket(f HostFacts) (string, bool) {
	paths := privateControllerSockets(f)
	if len(paths) != 1 {
		return "", false
	}
	return paths[0], true
}

func withSocket(host ControllerHostFacts, p string, s SocketFacts) ControllerHostFacts {
	sockets := make(map[string]SocketFacts, len(host.Sockets)+1)
	for k, v := range host.Sockets {
		sockets[k] = v
	}
	sockets[p] = s
	host.Sockets = sockets
	return host
}

// checkLearningRedis requires a socket-only Redis no tenant can reach, with
// a finite maxmemory and noeviction (spec 6.3).
func checkLearningRedis(c *learningCheck, f HostFacts) {
	r := f.Redis
	switch {
	case f.LearningDumps.Err != nil:
		c.add(ReasonBackendUnavailable, "CSM cannot read rspamd's loaded configuration")
		return
	case r.Endpoint == "":
		c.add(ReasonUnsafe, "CSM cannot identify the one Redis server fuzzy storage uses")
		return
	case !r.Unix:
		c.add(ReasonUnsafe, "fuzzy storage uses Redis over TCP; learning needs a Unix socket only")
		return
	case r.Unprotected:
		c.add(ReasonUnsafe, "the Redis socket's owner, directories or peer do not prove that Redis serves it")
		return
	case r.Socket.Err != nil || r.Socket.Missing:
		c.add(ReasonBackendUnavailable, "the Redis socket cannot be checked")
		return
	}
	// A protected socket as well as protected directories (spec 6.3):
	// no access for others and no ACL CSM cannot evaluate.
	if r.Socket.Socket.Mode.Perm()&0o007 != 0 || r.Socket.Socket.ExtACL {
		c.add(ReasonUnsafe, "the Redis socket is open to other users or carries extra ACL entries")
		return
	}
	if why := redisExposure(r, f.ControllerHost.RspamdUser, f.AccountNames, f.AccountNamesErr); why != "" {
		c.add(ReasonUnsafe, why)
		return
	}
	// Successful CONFIG reads remain evidence even when a later INFO
	// request fails. Definite exposure takes precedence over that outage.
	switch {
	case r.Port != "" && r.Port != "0":
		c.add(ReasonUnsafe, "Redis also listens on TCP; set port 0")
	case r.TLSPort != "" && r.TLSPort != "0":
		c.add(ReasonUnsafe, "Redis also listens on TLS TCP; set tls-port 0")
	case r.MaxMemoryKnown && r.MaxMemory == 0:
		c.add(ReasonUnsafe, "Redis has no maxmemory limit")
	case r.Policy != "" && r.Policy != "noeviction":
		c.add(ReasonUnsafe, "Redis can evict keys; set maxmemory-policy noeviction")
	}
	if r.Err != nil {
		c.add(ReasonBackendUnavailable, "Redis did not answer CSM's read-only checks")
		return
	}
	switch {
	case r.Port != "0":
		c.add(ReasonUnsafe, "Redis also listens on TCP; set port 0")
	case r.TLSPort != "" && r.TLSPort != "0":
		c.add(ReasonUnsafe, "Redis also listens on TLS over TCP; set tls-port 0")
	case r.MaxMemory == 0:
		c.add(ReasonUnsafe, "Redis has no maxmemory limit")
	case r.Policy != "noeviction":
		c.add(ReasonUnsafe, "Redis can evict keys; set maxmemory-policy noeviction")
	case r.AppendOnly != "yes" && (!r.SaveKnown || r.Save == ""):
		c.add(ReasonRedisPersistence, "Redis keeps no data across a restart; learned hashes are rebuilt from stored anchors")
	}
}

// redisExposure judges the Redis socket like a controller socket: its owner
// and root are trusted, and a group member counts as another user unless it
// is root, redis or rspamd's service user. Shared users such as nobody can
// run tenant code, so only these names are trusted, and redis or rspamd's
// user only while the account list is readable and no account carries the
// name. Unknown group members count as other users.
func redisExposure(r RedisFacts, rspamdUser string, accounts map[string]bool, accountsErr error) string {
	owner := r.Socket.Socket.UID
	host := ControllerHostFacts{Sockets: map[string]SocketFacts{r.Endpoint: r.Socket}, RspamdUID: owner, GroupMembers: map[int][]string{}}
	trusted := func(m string) bool {
		if m == "root" {
			return true
		}
		if accountsErr != nil || accounts[m] {
			return false
		}
		return m == "redis" || (rspamdUser != "" && m == rspamdUser)
	}
	if r.GroupMembers != nil {
		others := []string{}
		for _, m := range r.GroupMembers {
			if !trusted(m) {
				others = append(others, m)
			}
		}
		host.GroupMembers[r.Socket.Socket.GID] = others
	}
	why := unixExposure(ControllerListener{Unix: true, Path: r.Endpoint}, host)
	if why == "" {
		return ""
	}
	return fmt.Sprintf("the Redis socket: %s", why)
}

// checkLearningLogs requires rspamd's log to be unreadable to tenants (spec
// 11): file permissions, or CageFS confining every account with no rspamd
// log in its skeleton.
func checkLearningLogs(c *learningCheck, f HostFacts) {
	exposed, _ := f.RspamdLog.exposed(f.Socket.RspamdUID, func(gid int) bool {
		return !f.ControllerHost.groupHasOthers(gid)
	})
	if !exposed {
		return
	}
	cage := f.CageFS
	if cage.Err == nil && cage.Enabled && cage.DisabledUsers == 0 && !cage.SkeletonHasRspamdLog && cageFSProtectsLog(cage, f.RspamdLog) {
		return
	}
	if f.RspamdLog.Err != nil || cage.Err != nil {
		c.add(ReasonBackendUnavailable, "CSM cannot check who can read rspamd's log")
		return
	}
	c.add(ReasonUnsafe, "rspamd's log, which records learned digests, is readable by other users")
}

func cageFSProtectsLog(cage CageFSFacts, log LogFacts) bool {
	// The skeleton probe proves exclusion of one directory, not syslog,
	// journal output, arbitrary log files or symlink destinations.
	if log.Err != nil || log.Type != "file" || cage.ExcludedLogDir == "" ||
		!filepath.IsAbs(log.Path) || filepath.Clean(log.Path) != log.Path ||
		!ancestorOf(cage.ExcludedLogDir, log.Path) || len(log.Parents) == 0 {
		return false
	}
	for _, p := range log.Parents {
		if !p.Mode.IsDir() {
			return false
		}
	}
	return log.Missing || log.File.Mode.IsRegular()
}

// checkLearningConflicts finds operator fuzzy configuration CSM's override
// would hide (spec 6.1). Once CSM's files are installed, verification of the
// loaded rules takes over.
func checkLearningConflicts(c *learningCheck, s Settings, f HostFacts) {
	for _, t := range f.Targets {
		if t.Path == RoundcubeIncludePath || !isLearningPath(t.Path) {
			continue
		}
		if err := OptionalUsable(t); err != nil {
			c.add(ReasonConfigConflict, "a learning file CSM would write belongs to someone else or cannot be written safely")
			return
		}
	}
	if f.LearningDumps.Err != nil {
		return
	}
	if learningInstalled(f) {
		checkLearningStillLoaded(c, s, f)
		return
	}
	rules, err := loadedFuzzyRules(f.LearningDumps.FuzzyCheck)
	if err != nil {
		c.add(ReasonConfigConflict, "CSM cannot read rspamd's loaded fuzzy rules")
		return
	}
	for name := range rules {
		if name != stockFuzzyRule {
			c.add(ReasonConfigConflict, "rspamd loads a local fuzzy rule that CSM's override would hide")
			return
		}
	}
	enabled, err := fuzzyWorkerEnabled(f.LearningDumps.Worker)
	if err != nil {
		c.add(ReasonConfigConflict, "CSM cannot read rspamd's loaded fuzzy worker")
	} else if enabled {
		c.add(ReasonConfigConflict, "rspamd runs a local fuzzy worker that CSM's override would replace")
	}
}

// checkLearningStillLoaded compares what rspamd loads now with CSM's files,
// on every pass after install (spec 6.1, 6.2): a runtime weight change, a
// higher-priority group cap or score rescaling is a conflict. Files that
// drifted from CSM's text are left to the next apply, whose own check
// verifies the result.
func checkLearningStillLoaded(c *learningCheck, s Settings, f HostFacts) {
	if !learningFilesCurrent(s, f) {
		return
	}
	d := f.LearningDumps
	if d.SymbolsErr != nil {
		c.add(ReasonBackendUnavailable, "CSM cannot read the effective learning weights from rspamd's controller")
		return
	}
	actions, err := ParseActions([]byte(f.RspamdActions.Stdout))
	if f.RspamdActions.Err != nil || err != nil {
		c.add(ReasonBackendUnavailable, "rspamd's actions are not readable")
		return
	}
	if err := CheckLearningLoaded(d.FuzzyCheck, d.Worker, d.Group, d.Symbols, actions, s.LearningKeys); err != nil {
		c.add(ReasonConfigConflict, "rspamd no longer loads CSM's learning configuration as written: "+err.Error())
	}
}

// learningFilesCurrent reports whether every learning file holds exactly the
// text CSM renders for s.
func learningFilesCurrent(s Settings, f HostFacts) bool {
	files, err := RenderLearning(s)
	if err != nil {
		return false
	}
	for _, t := range f.Targets {
		if want, ok := files[t.Path]; ok && (t.Missing || t.Err != nil || t.Content != want) {
			return false
		}
	}
	return true
}

// loadedFuzzyRules reads the rules of `rspamadm configdump -j fuzzy_check`:
// an object keyed by rule name with one rule, a list of single-key objects
// with several. A rule name seen twice is an error.
func loadedFuzzyRules(dump []byte) (map[string]map[string]json.RawMessage, error) {
	out := map[string]map[string]json.RawMessage{}
	if len(dump) == 0 {
		return out, nil
	}
	root, err := dumpObjectAs[json.RawMessage](dump, "fuzzy_check")
	if err != nil {
		return nil, err
	}
	raw, ok := root["rule"]
	if !ok {
		return out, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("fuzzy_check rule is null")
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		entries = []json.RawMessage{raw}
	}
	for _, entry := range entries {
		named, err := dumpObjectAs[json.RawMessage](entry, "fuzzy_check rule")
		if err != nil {
			return nil, err
		}
		for name, body := range named {
			fields, err := dumpObjectAs[json.RawMessage](body, "fuzzy_check rule")
			if err != nil {
				return nil, err
			}
			if _, dup := out[name]; dup {
				return nil, errors.New("fuzzy_check names a rule twice")
			}
			out[name] = fields
		}
	}
	return out, nil
}

func isLearningPath(p string) bool {
	for _, lp := range LearningPaths() {
		if p == lp {
			return true
		}
	}
	return false
}

// fuzzyWorkerEnabled reports whether the worker section holds an enabled
// fuzzy worker, in either form rspamd prints.
func fuzzyWorkerEnabled(section json.RawMessage) (bool, error) {
	if len(section) == 0 {
		return false, nil
	}
	var entries []json.RawMessage
	if trimmed := bytes.TrimSpace(section); len(trimmed) > 0 && trimmed[0] == '[' {
		if json.Unmarshal(section, &entries) != nil {
			return false, errors.New("worker section is not readable")
		}
	} else {
		entries = []json.RawMessage{section}
	}
	for _, entry := range entries {
		fields, err := dumpObjectAs[json.RawMessage](entry, "worker")
		if err != nil {
			return false, err
		}
		if raw, typed := fields["type"]; typed {
			var kind string
			if json.Unmarshal(raw, &kind) != nil || kind == "" || strings.ContainsRune(kind, '\x00') {
				return false, errors.New("worker type is not readable")
			}
			if kind != "fuzzy" {
				continue
			}
		} else if raw, ok := fields["fuzzy"]; ok {
			fields, err = dumpObjectAs[json.RawMessage](raw, "fuzzy worker")
			if err != nil {
				return false, err
			}
		} else {
			continue
		}
		disabled, err := disabledWorker(fields)
		if err != nil {
			return false, err
		}
		if !disabled {
			return true, nil
		}
	}
	return false, nil
}

// roundcubeUsable decides the Junk-button include alone (spec 6.4): any
// failure reports it and leaves learning on.
func roundcubeUsable(c *learningCheck, f HostFacts) bool {
	rc := f.Roundcube
	if rc.Err != nil || !rc.IncludeMechanism || !rc.PHP || OptionalUsable(rc.Include) != nil {
		detail := "the webmail Junk-button include cannot be installed or verified; learning continues without it"
		if inc := rc.Include; !inc.Missing && inc.Err == nil && inc.Content != "" && !ManagedFor(inc.Kind, inc.Content) {
			detail = "another file holds the webmail Junk-button include path; learning continues without CSM's include"
		}
		c.add(ReasonRoundcube, detail)
		return false
	}
	return true
}

// LearningScoringLoaded reports whether the full `rspamadm configdump -j`
// shows CSM's learning rules loaded in an enabled fuzzy_check module. An
// unreadable dump says nothing.
func LearningScoringLoaded(fullDump []byte) bool {
	root, err := dumpObjectAs[json.RawMessage](fullDump, "configdump")
	if err != nil {
		return false
	}
	section, ok := root["fuzzy_check"]
	if !ok {
		return false
	}
	fields, err := dumpObjectAs[json.RawMessage](section, "fuzzy_check")
	if err != nil {
		return false
	}
	var enabled bool
	if raw, ok := fields["enabled"]; ok && json.Unmarshal(raw, &enabled) == nil && !enabled {
		return false
	}
	rules, err := loadedFuzzyRules(section)
	if err != nil {
		return false
	}
	_, scan := rules["csm"]
	_, learn := rules["csm_learn"]
	return scan || learn
}
