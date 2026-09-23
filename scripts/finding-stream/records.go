package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/firewall"
)

// Action and firewall records are rebuilt field by field. Nothing an input
// row carries reaches the output unless a rule here names it, and every value
// that does is either a closed vocabulary or a pseudonym this run emitted.
// Findings keep their free text (scrubbed); these rows keep none.

const recordFormatVersion = 1

// idKind separates the salted identifier domains: the same raw value maps to
// unrelated ids as a finding and as an action.
type idKind string

const (
	idFinding  idKind = "finding"
	idAction   idKind = "action"
	idIncident idKind = "incident"
	idTarget   idKind = "target"
)

var idPrefixes = map[idKind]string{idFinding: "fid", idAction: "aid", idIncident: "iid", idTarget: "tid"}

// recordError is a fixed refusal code. It never carries input bytes, so a
// refusal can be reported without repeating what the record held.
type recordError string

func (e recordError) Error() string { return string(e) }

const (
	errRecordVersion recordError = "record: unsupported version"
	errRecordTime    recordError = "record: missing timestamp"
	errUnknownOp     recordError = "record: unreviewed operation"
	errUnknownAction recordError = "record: unreviewed action"
	errUnknownActor  recordError = "record: unreviewed actor"
	errUnknownResult recordError = "record: unreviewed result"
	errUnknownSource recordError = "record: unreviewed source"
	errDuration      recordError = "record: duration is not positive"
	errTargetAddress recordError = "record: target is not an address, network or endpoint"
	errTargetMissing recordError = "record: missing target"
	errRowUnverified recordError = "record: transformed row failed verification"

	errNotObject    recordError = "json: not one object"
	errSyntax       recordError = "json: malformed"
	errUnknownField recordError = "json: unclassified field"
	errDuplicateKey recordError = "json: repeated field"
	errNull         recordError = "json: null value"
	errTrailing     recordError = "json: data after the object"
	errType         recordError = "json: field has the wrong type"
	errLineTooLong  recordError = "json: line over the limit"
	errTooLong      recordError = "json: field over its length limit"
	errTooMany      recordError = "json: array over its element limit"
	errTooDeep      recordError = "json: nesting over the parent limit"
)

// Offline parser limits. They bound what one hostile line can make this tool
// hold; they are not response policy.
const (
	maxLineBytes   = 16 << 20
	maxTextBytes   = 64 << 10
	maxScalarBytes = 4 << 10
	maxArrayItems  = 1024
	maxParentDepth = 32
	// A raw id shorter than this is left to the typed verifier: scanning
	// finding text for "a1" or "csm" would flag ordinary words.
	minRawIDBytes = 8
)

type opShape int

const (
	opFirewall opShape = iota
	opProcess
	opFile
)

// actionOps are the operations whose action-log writers were audited; each
// is a privops ID. Another operation's target forms are unknown, so its rows
// refuse until reviewed.
var actionOps = map[string]opShape{
	"respond.block_ip":           opFirewall,
	"operate.manual_firewall":    opFirewall,
	"integrate.firewall_ruleset": opFirewall,
	"respond.kill_process":       opProcess,
	"respond.quarantine_file":    opFile,
	"respond.clean_file":         opFile,
}

// firewallActionLogActions is every action a firewall-family writer records,
// legacy and durable. The same action reaches different operations depending
// on actor and origin, so pairing is checked per family, not per operation.
var firewallActionLogActions = map[string]bool{
	"allow": true, "allow_port": true, "apply": true, "block": true, "block_subnet": true,
	"configure_port_allow": true, "evict_temp": true, "flush": true, "permblock": true, "promote": true,
	"remove_allow": true, "remove_port_allow": true, "state": true, "temp_allow": true,
	"temp_allow_expired": true, "temp_subnet_expired": true, "unblock": true, "unblock_subnet": true,
}

// manualFirewallFileActions target a rollback file, not an address.
var manualFirewallFileActions = map[string]bool{"rollback": true, "rollback_config": true}

// Whole-ruleset actions name a fixed token ("csm", "*") or nothing.
var firewallOpaqueActions = map[string]bool{"apply": true, "flush": true, "state": true}

// firewallAuditActions is what the legacy firewall audit log records.
var firewallAuditActions = map[string]bool{
	"allow": true, "allow_port": true, "block": true, "block_subnet": true, "evict_temp": true, "flush": true,
	"permblock": true, "remove_allow": true, "remove_port_allow": true, "temp_allow": true,
	"temp_allow_expired": true, "temp_subnet_expired": true, "unblock": true, "unblock_subnet": true,
}

var firewallSources = map[string]bool{
	firewall.SourceUnknown: true, firewall.SourceWebUI: true, firewall.SourceCLI: true,
	firewall.SourceAutoResponse: true, firewall.SourceChallenge: true, firewall.SourceWhitelist: true,
	firewall.SourceDynDNS: true, firewall.SourceSystem: true,
}

var actionActors = map[string]bool{string(actionlog.Daemon): true, string(actionlog.CLI): true, string(actionlog.WebUI): true}

// Durable lifecycle rows record their outcome phase in the result field, so
// verified and unknown sit beside the legacy results. Applied is a claim by
// the writer, not a verification.
var actionResults = map[string]bool{
	string(actionlog.Applied): true, string(actionlog.DryRun): true, string(actionlog.Failed): true,
	string(actionlog.Refused): true, "verified": true, "unknown": true,
}

// Reasons are free text; only the producing path survives. Matching is on
// exact bytes: a lower-cased or prefixed variant is not the producer's text.
var reasonExact = map[string]string{
	"temp deny limit reached; evicted soonest-expiring entry": "temp_limit_eviction",
	"central-intel (locally corroborated)":                    "central_intel",
	"CSM whitelist: customer IP":                              "whitelist",
	"CSM temp whitelist":                                      "whitelist",
	"CSM bulk whitelist":                                      "whitelist",
	"manual process termination":                              "operator",
	"AF_ALG socket open":                                      "af_alg",
}

var reasonPrefixes = []struct{ prefix, kind string }{
	{"CSM auto-block (subnet): ", "scan_subnet"},
	{"CSM auto-block (asn-crawl): ", "asn_crawl"},
	{"CSM auto-block: ", "scan"},
	{"CSM challenge-timeout: ", "challenge_timeout"},
	{"challenge timeout: ", "challenge_timeout"},
	{"CSM credential_spray: ", "credential_spray"},
	{"CSM incident: ", "incident"},
	{"Auto-netblock: ", "netblock"},
	{"PERMBLOCK: ", "permblock"},
	{"dyndns: ", "dyndns"},
	{"source: ", "allow_source"},
	{"cleared ", "flush"},
}

var reasonSuffixes = []struct{ suffix, kind string }{
	{" via CLI", "operator_cli"},
	{" via CSM Web UI", "operator_webui"},
}

var reasonKinds = func() map[string]bool {
	kinds := map[string]bool{"empty": true, "other": true}
	for _, k := range reasonExact {
		kinds[k] = true
	}
	for _, p := range reasonPrefixes {
		kinds[p.kind] = true
	}
	for _, s := range reasonSuffixes {
		kinds[s.kind] = true
	}
	return kinds
}()

func reasonKind(reason string) string {
	if reason == "" {
		return "empty"
	}
	if kind, ok := reasonExact[reason]; ok {
		return kind
	}
	for _, p := range reasonPrefixes {
		if strings.HasPrefix(reason, p.prefix) {
			return p.kind
		}
	}
	for _, s := range reasonSuffixes {
		if strings.HasSuffix(reason, s.suffix) {
			return s.kind
		}
	}
	return "other"
}

// anonTarget is a typed target: a mapped address with its prefix length or
// port and protocol as numbers, or a salted id for a path or opaque token.
type anonTarget struct {
	Target       string `json:"target,omitempty"`
	TargetKind   string `json:"target_kind"`
	TargetPrefix int    `json:"target_prefix,omitempty"`
	TargetPort   int    `json:"target_port,omitempty"`
	TargetProto  string `json:"target_proto,omitempty"`
}

// anonAction is the only shape an action record leaves the host in.
type anonAction struct {
	V             int       `json:"v"`
	Format        int       `json:"format_version"`
	Timestamp     time.Time `json:"ts"`
	Hostname      string    `json:"hostname,omitempty"`
	Account       string    `json:"account,omitempty"`
	Op            string    `json:"op"`
	Action        string    `json:"action,omitempty"`
	Actor         string    `json:"actor"`
	ActorIP       string    `json:"actor_ip,omitempty"`
	DurationNS    int64     `json:"duration_ns,omitempty"`
	FindingID     string    `json:"finding_id,omitempty"`
	IncidentID    string    `json:"incident_id,omitempty"`
	ActionID      string    `json:"action_id,omitempty"`
	ActionVersion uint64    `json:"action_version,omitempty"`
	UndoOf        string    `json:"undo_of,omitempty"`
	anonTarget
	ReasonKind   string `json:"reason_kind"`
	Result       string `json:"result"`
	HasError     bool   `json:"has_error"`
	BeforeExists *bool  `json:"before_exists,omitempty"`
	AfterExists  *bool  `json:"after_exists,omitempty"`
}

// anonFirewallAudit is the only shape a firewall audit entry leaves in. The
// legacy entry has no ids, so nothing here can be joined to an action.
type anonFirewallAudit struct {
	Format    int       `json:"format_version"`
	Timestamp time.Time `json:"ts"`
	Action    string    `json:"action"`
	anonTarget
	ReasonKind string `json:"reason_kind"`
	Source     string `json:"source"`
	DurationNS int64  `json:"duration_ns,omitempty"`
}

// ID maps a raw identifier to a salted one with at least 128 bits of digest.
// It keeps case and domain-separates kinds, unlike the short name labels.
func (a *Anonymizer) ID(kind idKind, raw string) string {
	if raw == "" {
		return ""
	}
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte("id\x00"))
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(raw))
	id := idPrefixes[kind] + "-" + hex.EncodeToString(mac.Sum(nil)[:16])
	a.ids[id] = kind
	return a.remember(id)
}

// LearnActions collects the identities action records carry, so finding
// text is scrubbed of them too and the leak check knows the raw ids.
func (a *Anonymizer) LearnActions(records []actionlog.Record) {
	for i := range records {
		r := &records[i]
		a.learnHost(r.Hostname)
		a.learnAccount(r.Account)
		for _, text := range []string{r.Target, r.Reason, r.Error, r.ActorDetail, r.Undo, r.RecoveryPath} {
			a.learnText(text)
		}
		for _, arg := range r.Command {
			a.learnText(arg)
		}
		for _, id := range []string{r.FindingID, r.IncidentID, r.ActionID, r.UndoOf} {
			a.learnRawID(id)
		}
	}
}

func (a *Anonymizer) learnRawID(id string) {
	if len(id) < minRawIDBytes {
		return
	}
	if strings.Trim(id, idTokenBytes) == "" {
		a.rawIDs[id] = struct{}{}
		return
	}
	a.rawIDText[id] = struct{}{}
}

// Action returns the typed, anonymized copy of an action record.
func (a *Anonymizer) Action(r actionlog.Record) (anonAction, error) {
	if r.V != actionlog.SchemaVersion {
		return anonAction{}, errRecordVersion
	}
	if r.Timestamp.IsZero() {
		return anonAction{}, errRecordTime
	}
	shape, ok := actionOps[r.Op]
	if !ok {
		return anonAction{}, errUnknownOp
	}
	if !actionAllowed(shape, r.Op, r.Action) {
		return anonAction{}, errUnknownAction
	}
	if !actionActors[string(r.Actor)] {
		return anonAction{}, errUnknownActor
	}
	if !actionResults[string(r.Result)] {
		return anonAction{}, errUnknownResult
	}
	target, err := a.actionTarget(shape, r.Action, r.Target)
	if err != nil {
		return anonAction{}, err
	}
	out := anonAction{
		V: r.V, Format: recordFormatVersion, Timestamp: r.Timestamp,
		Hostname: a.Host(r.Hostname), Account: a.recordAccount(r.Account),
		Op: r.Op, Action: r.Action, Actor: string(r.Actor),
		FindingID: a.ID(idFinding, r.FindingID), IncidentID: a.ID(idIncident, r.IncidentID),
		ActionID: a.ID(idAction, r.ActionID), ActionVersion: r.ActionVersion, UndoOf: a.ID(idAction, r.UndoOf),
		anonTarget: target, ReasonKind: reasonKind(r.Reason), Result: string(r.Result), HasError: r.Error != "",
	}
	a.actorDetail(&out, r.ActorDetail)
	if r.Before != nil {
		exists := r.Before.Exists
		out.BeforeExists = &exists
	}
	if r.After != nil {
		exists := r.After.Exists
		out.AfterExists = &exists
	}
	return out, nil
}

func actionAllowed(shape opShape, op, action string) bool {
	if shape != opFirewall {
		return action == ""
	}
	return firewallActionLogActions[action] || (op == "operate.manual_firewall" && manualFirewallFileActions[action])
}

// Unlike Account, a new row maps system users and bare uids too: a typed row
// has no sentence for "root" to explain.
func (a *Anonymizer) recordAccount(raw string) string {
	if raw == "" {
		return ""
	}
	return a.remember("acct-" + a.label("account", raw))
}

// Only two actor details are kept: a positive block lease, and an operator
// address, which maps like any other address. Executable paths and command
// names are dropped.
func (a *Anonymizer) actorDetail(out *anonAction, detail string) {
	if rest, ok := strings.CutPrefix(detail, "expires in "); ok {
		if d, err := time.ParseDuration(rest); err == nil && d > 0 {
			out.DurationNS = int64(d)
		}
		return
	}
	if addr, ok := parseTargetAddr(detail); ok {
		out.ActorIP = a.mapAddr(addr)
	}
}

func (a *Anonymizer) actionTarget(shape opShape, action, raw string) (anonTarget, error) {
	switch {
	case shape == opFile || manualFirewallFileActions[action]:
		return a.opaqueTarget(raw, "path")
	case shape == opProcess:
		return a.opaqueTarget(raw, "opaque")
	case firewallOpaqueActions[action] && raw != "":
		return a.opaqueTarget(raw, "opaque")
	}
	return a.addressTarget(raw)
}

func (a *Anonymizer) opaqueTarget(raw, kind string) (anonTarget, error) {
	if raw == "" {
		return anonTarget{}, errTargetMissing
	}
	return anonTarget{Target: a.ID(idTarget, raw), TargetKind: kind}, nil
}

// addressTarget parses the forms the firewall writes: an address, a network,
// "address:port/proto" (IPv6 unbracketed, as fmt.Sprintf emits it) or
// nothing. The address map is not topology preserving: two pseudonyms say
// nothing about whether their networks overlap.
func (a *Anonymizer) addressTarget(raw string) (anonTarget, error) {
	if raw == "" {
		return anonTarget{TargetKind: "empty"}, nil
	}
	if head, proto, ok := cutLast(raw, '/'); ok && (proto == "tcp" || proto == "udp") {
		host, portText, ok := cutLast(head, ':')
		if !ok {
			return anonTarget{}, errTargetAddress
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
			return anonTarget{}, errTargetAddress
		}
		addr, ok := parseTargetAddr(host)
		if !ok {
			return anonTarget{}, errTargetAddress
		}
		return anonTarget{Target: a.mapAddr(addr), TargetKind: "endpoint", TargetPort: int(port), TargetProto: proto}, nil
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return anonTarget{}, errTargetAddress
		}
		addr, bits := p.Addr(), p.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return anonTarget{}, errTargetAddress
			}
			addr, bits = addr.Unmap(), bits-96
		}
		// No writer blocks a whole address family.
		if bits == 0 {
			return anonTarget{}, errTargetAddress
		}
		network := netip.PrefixFrom(addr, bits).Masked()
		return anonTarget{Target: a.mapAddr(network.Addr()), TargetKind: "cidr", TargetPrefix: bits}, nil
	}
	addr, ok := parseTargetAddr(raw)
	if !ok {
		return anonTarget{}, errTargetAddress
	}
	return anonTarget{Target: a.mapAddr(addr), TargetKind: "ip"}, nil
}

func cutLast(s string, sep byte) (string, string, bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// An IPv4-mapped address is the IPv4 address, as the firewall treats it;
// the pseudonym then agrees with the one finding text gets.
func parseTargetAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (a *Anonymizer) mapAddr(addr netip.Addr) string {
	if addr.Is4() {
		return a.IPv4(addr.String())
	}
	return a.IPv6(addr.String())
}

// FirewallAudit returns the typed, anonymized copy of a firewall audit entry.
func (a *Anonymizer) FirewallAudit(e firewall.AuditEntry) (anonFirewallAudit, error) {
	if e.Timestamp.IsZero() {
		return anonFirewallAudit{}, errRecordTime
	}
	if !firewallAuditActions[e.Action] {
		return anonFirewallAudit{}, errUnknownAction
	}
	source := e.Source
	if source == "" {
		source = firewall.SourceUnknown
	}
	if !firewallSources[source] {
		return anonFirewallAudit{}, errUnknownSource
	}
	var duration time.Duration
	if e.Duration != "" {
		d, err := time.ParseDuration(e.Duration)
		if err != nil || d <= 0 {
			return anonFirewallAudit{}, errDuration
		}
		duration = d
	}
	target, err := a.addressTarget(e.IP)
	if err != nil {
		return anonFirewallAudit{}, err
	}
	return anonFirewallAudit{
		Format: recordFormatVersion, Timestamp: e.Timestamp, Action: e.Action, anonTarget: target,
		ReasonKind: reasonKind(e.Reason), Source: source, DurationNS: int64(duration),
	}, nil
}

// VerifyAction checks a transformed row independently of the transform:
// every value is a closed vocabulary or a token this run emitted, of the
// right kind. A raw value shaped like a pseudonym is not emitted and fails.
func (a *Anonymizer) VerifyAction(o anonAction) error {
	shape, ok := actionOps[o.Op]
	valid := ok && o.V == actionlog.SchemaVersion && o.Format == recordFormatVersion && !o.Timestamp.IsZero() &&
		actionAllowed(shape, o.Op, o.Action) && actionActors[o.Actor] && actionResults[o.Result] &&
		reasonKinds[o.ReasonKind] && o.DurationNS >= 0 &&
		a.emittedName(o.Hostname, "host-") && a.emittedName(o.Account, "acct-") &&
		(o.ActorIP == "" || a.emittedAddress(o.ActorIP)) &&
		a.emittedID(o.FindingID, idFinding) && a.emittedID(o.IncidentID, idIncident) &&
		a.emittedID(o.ActionID, idAction) && a.emittedID(o.UndoOf, idAction) &&
		a.validTarget(o.anonTarget, actionTargetKinds(shape, o.Action))
	if !valid {
		return errRowUnverified
	}
	return nil
}

func actionTargetKinds(shape opShape, action string) map[string]bool {
	switch {
	case shape == opFile || manualFirewallFileActions[action]:
		return map[string]bool{"path": true}
	case shape == opProcess:
		return map[string]bool{"opaque": true}
	case firewallOpaqueActions[action]:
		return map[string]bool{"opaque": true, "empty": true}
	}
	return addressTargetKinds
}

var addressTargetKinds = map[string]bool{"ip": true, "cidr": true, "endpoint": true, "empty": true}

// VerifyFirewallAudit is VerifyAction for firewall audit rows.
func (a *Anonymizer) VerifyFirewallAudit(o anonFirewallAudit) error {
	valid := o.Format == recordFormatVersion && !o.Timestamp.IsZero() && firewallAuditActions[o.Action] &&
		firewallSources[o.Source] && reasonKinds[o.ReasonKind] && o.DurationNS >= 0 &&
		a.validTarget(o.anonTarget, addressTargetKinds)
	if !valid {
		return errRowUnverified
	}
	return nil
}

func (a *Anonymizer) validTarget(t anonTarget, kinds map[string]bool) bool {
	if !kinds[t.TargetKind] {
		return false
	}
	switch t.TargetKind {
	case "empty":
		return t == anonTarget{TargetKind: "empty"}
	case "ip":
		return a.emittedAddress(t.Target) && t == anonTarget{Target: t.Target, TargetKind: "ip"}
	case "cidr":
		addr, err := netip.ParseAddr(t.Target)
		return err == nil && a.emittedAddress(t.Target) && t.TargetPrefix >= 1 && t.TargetPrefix <= addr.BitLen() &&
			t.TargetPort == 0 && t.TargetProto == ""
	case "endpoint":
		return a.emittedAddress(t.Target) && t.TargetPrefix == 0 && t.TargetPort >= 1 && t.TargetPort <= 65535 &&
			(t.TargetProto == "tcp" || t.TargetProto == "udp")
	default:
		return a.emittedID(t.Target, idTarget) && t.Target != "" && t.TargetPrefix == 0 && t.TargetPort == 0 && t.TargetProto == ""
	}
}

var (
	anonIPv4Space = netip.MustParsePrefix("198.18.0.0/15")
	anonIPv6Space = netip.MustParsePrefix("2001:db8::/32")
)

func (a *Anonymizer) emittedAddress(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && a.isPseudonym(s) && (anonIPv4Space.Contains(addr) || anonIPv6Space.Contains(addr))
}

func (a *Anonymizer) emittedName(s, prefix string) bool {
	return s == "" || (strings.HasPrefix(s, prefix) && a.isPseudonym(s))
}

func (a *Anonymizer) emittedID(s string, kind idKind) bool {
	if s == "" {
		return true
	}
	got, ok := a.ids[s]
	return ok && got == kind
}

// decodeStrict decodes exactly one JSON object into v. Go's decoder matches
// keys case-insensitively, keeps the last of repeated keys and stops after
// the first value, so a token pass first checks every key against the exact
// field names of v, rejects duplicates, nulls, overlong values and anything
// after the object, and only then decodes.
func decodeStrict(data []byte, v any) error {
	if len(data) > maxLineBytes {
		return errLineTooLong
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if delim, ok := tok.(json.Delim); err != nil || !ok || delim != '{' {
		if err != nil && !errors.Is(err, io.EOF) {
			return errSyntax
		}
		return errNotObject
	}
	if err := checkObject(dec, reflect.TypeOf(v).Elem(), map[reflect.Type]int{}); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errTrailing
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(v); err != nil {
		return errType
	}
	// More reports only whether a value follows in the current array or
	// object; a second Decode is the check that nothing follows at all.
	if err := strict.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errTrailing
	}
	return nil
}

var timeType = reflect.TypeFor[time.Time]()

// longTextFields may hold free text or paths; every other scalar is an id,
// name, enum or address.
var longTextFields = map[string]bool{
	"message": true, "details": true, "file_path": true, "target": true, "reason": true, "error": true,
	"undo": true, "recovery_path": true, "actor_detail": true, "command": true, "exe": true, "cmdline": true,
}

// checkObject reads the keys and values of an object whose '{' was consumed.
// depth counts open objects per type, which bounds recursive process parents.
func checkObject(dec *json.Decoder, t reflect.Type, depth map[reflect.Type]int) error {
	if t.Kind() != reflect.Struct || t == timeType {
		return errType
	}
	if depth[t] > maxParentDepth {
		return errTooDeep
	}
	depth[t]++
	defer func() { depth[t]-- }()
	fields := jsonFieldTypes(t)
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errSyntax
		}
		key, _ := tok.(string)
		field, ok := fields[key]
		if !ok {
			return errUnknownField
		}
		if seen[strings.ToLower(key)] {
			return errDuplicateKey
		}
		seen[strings.ToLower(key)] = true
		if err := checkValue(dec, field, key, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errSyntax
	}
	return nil
}

func checkValue(dec *json.Decoder, t reflect.Type, key string, depth map[reflect.Type]int) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return errSyntax
	}
	limit := maxScalarBytes
	if longTextFields[key] {
		limit = maxTextBytes
	}
	switch tok := tok.(type) {
	case nil:
		return errNull
	case json.Delim:
		switch tok {
		case '{':
			return checkObject(dec, t, depth)
		case '[':
			if t.Kind() != reflect.Slice {
				return errType
			}
			for n := 0; dec.More(); n++ {
				if n == maxArrayItems {
					return errTooMany
				}
				if err := checkValue(dec, t.Elem(), key, depth); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return errSyntax
			}
			return nil
		}
		return errSyntax
	case string:
		if t.Kind() != reflect.String && t != timeType {
			return errType
		}
		if len(tok) > limit {
			return errTooLong
		}
	case json.Number:
		switch t.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
		default:
			return errType
		}
		if len(tok) > maxScalarBytes {
			return errTooLong
		}
	case bool:
		if t.Kind() != reflect.Bool {
			return errType
		}
	}
	return nil
}

var fieldTypeCache sync.Map

// jsonFieldTypes maps the exact JSON names of t's fields to their types.
func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	if cached, ok := fieldTypeCache.Load(t); ok {
		return cached.(map[string]reflect.Type)
	}
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	fieldTypeCache.Store(t, fields)
	return fields
}
