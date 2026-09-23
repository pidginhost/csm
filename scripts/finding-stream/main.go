// Command finding-stream turns CSM audit logs into an anonymized finding
// stream for correlation and threshold calibration, optionally joined with
// the action log and the firewall audit log.
//
//	finding-stream anonymize --salt-file SALT --out findings.jsonl.gz \
//	    [--actions actions.jsonl --actions-out actions.jsonl.gz] \
//	    [--firewall-audit audit.jsonl --firewall-out firewall.jsonl.gz] \
//	    [--manifest manifest.json [--input-manifest inventory.json]] \
//	    audit.jsonl [audit.jsonl-*.gz ...]
//
// Inputs are plain or gzip JSONL. Findings keep their schema with every host,
// account, domain, mailbox and address replaced by a salted pseudonym; action
// and firewall rows are rebuilt from a closed allowlist. Every input is read,
// validated, transformed and checked for leaks before anything is written,
// and a refusal writes nothing. With --manifest the run also publishes a
// manifest of input and output digests, join counts and coverage, last, as
// the bundle's completion marker. The salt file is created on first use
// (mode 0600) and must be kept private and reused across hosts so their
// streams share pseudonyms. Collection is a read-only copy of the log files;
// nothing here runs on the monitored host.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "finding-stream:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error { return newRun().execute(args, stdout) }

// cliError is a fixed message. Errors leave the command only through these
// and recordError, so a refusal never repeats a path, a name or input bytes.
type cliError string

func (e cliError) Error() string { return string(e) }

const (
	errUsage             cliError = "usage: finding-stream anonymize --salt-file FILE --out FILE.jsonl.gz [--actions FILE --actions-out FILE.jsonl.gz] [--firewall-audit FILE --firewall-out FILE.jsonl.gz] [--manifest FILE [--input-manifest FILE]] INPUT [INPUT]"
	errUnpairedStream    cliError = "every --actions and --firewall-audit input needs its output flag, and every such output needs an input"
	errManifestRequired  cliError = "a joined run or an input manifest needs --manifest"
	errRevision          cliError = "a manifest needs a build of a known source revision without local changes"
	errOutputAlias       cliError = "an output must not replace an input, the salt, the input manifest or another output"
	errUnsafeDestination cliError = "an output path exists and is not a regular file"
	errDestination       cliError = "an output path cannot be inspected"
	errInputManifest     cliError = "the input manifest does not match the supplied inputs"
	errLeak              cliError = "leak check failed; nothing written"
	errPublish           cliError = "publication failed; previous outputs are unchanged"
	errRollback          cliError = "publication failed and previous outputs could not all be restored; recovery copies kept beside them"
	errSaltLoad          cliError = "salt: cannot read or create"
	errSaltUnsafe        cliError = "salt must be a regular file accessible only by its owner (mode 0600)"
	errSaltShort         cliError = "salt file is shorter than 32 bytes"
	errInputOpen         cliError = "cannot open"
	errInputGzip         cliError = "not a complete gzip stream"
	errInputRead         cliError = "read failed"
)

// inputError places a fixed code by stream kind, file ordinal and line.
type inputError struct {
	kind    streamKind
	ordinal int
	line    int
	code    error
}

func (e inputError) Error() string {
	if e.line == 0 {
		return fmt.Sprintf("%s input %d: %v", e.kind, e.ordinal, e.code)
	}
	return fmt.Sprintf("%s input %d line %d: %v", e.kind, e.ordinal, e.line, e.code)
}

func (e inputError) Unwrap() error { return e.code }

// anonymizeRun holds what a test may replace: the filesystem steps of
// publication, the build stamp and the three transforms. Production uses
// the real ones; a test swaps a transform to prove the verifier stands
// between a leaking transform and the output.
type anonymizeRun struct {
	ops      fileOps
	revision func() toolRevision
	event    func(*Anonymizer, alert.AuditEvent) alert.AuditEvent
	action   func(*Anonymizer, actionlog.Record) (anonAction, error)
	firewall func(*Anonymizer, firewall.AuditEntry) (anonFirewallAudit, error)
}

func newRun() *anonymizeRun {
	return &anonymizeRun{
		ops: osFileOps(), revision: readBuildRevision,
		event: (*Anonymizer).Event, action: (*Anonymizer).Action, firewall: (*Anonymizer).FirewallAudit,
	}
}

type options struct {
	saltPath, out, actionsOut, firewallOut, manifest, inputManifest string
	findings, actions, firewallAudits                               []string
}

type pathList []string

func (l *pathList) String() string     { return strings.Join(*l, ",") }
func (l *pathList) Set(v string) error { *l = append(*l, v); return nil }

func parseOptions(args []string) (options, error) {
	if len(args) == 0 || args[0] != "anonymize" {
		return options{}, errUsage
	}
	fs := flag.NewFlagSet("anonymize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o options
	fs.StringVar(&o.saltPath, "salt-file", ".cache/finding-streams/salt", "private salt; created when absent")
	fs.StringVar(&o.out, "out", "", "finding output (gzip JSONL)")
	fs.Var((*pathList)(&o.actions), "actions", "action log input; repeatable")
	fs.StringVar(&o.actionsOut, "actions-out", "", "action output (gzip JSONL)")
	fs.Var((*pathList)(&o.firewallAudits), "firewall-audit", "firewall audit log input; repeatable")
	fs.StringVar(&o.firewallOut, "firewall-out", "", "firewall audit output (gzip JSONL)")
	fs.StringVar(&o.manifest, "manifest", "", "bundle manifest, written last")
	fs.StringVar(&o.inputManifest, "input-manifest", "", "collector inventory of the inputs")
	// A flag error names the flag or value it rejected.
	if err := fs.Parse(args[1:]); err != nil {
		return options{}, errUsage
	}
	o.findings = fs.Args()
	all := append(append(append([]string{o.saltPath}, o.findings...), o.actions...), o.firewallAudits...)
	switch {
	case o.out == "" || len(o.findings) == 0 || containsEmpty(all):
		return options{}, errUsage
	case (len(o.actions) > 0) != (o.actionsOut != ""), (len(o.firewallAudits) > 0) != (o.firewallOut != ""):
		return options{}, errUnpairedStream
	case (len(o.actions) > 0 || len(o.firewallAudits) > 0 || o.inputManifest != "") && o.manifest == "":
		return options{}, errManifestRequired
	}
	return o, nil
}

func containsEmpty(list []string) bool {
	for _, s := range list {
		if s == "" {
			return true
		}
	}
	return false
}

func (o options) outputs() []string {
	var out []string
	for _, p := range []string{o.out, o.actionsOut, o.firewallOut, o.manifest} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (o options) protected() []string {
	p := append(append(append([]string{o.saltPath}, o.findings...), o.actions...), o.firewallAudits...)
	if o.inputManifest != "" {
		p = append(p, o.inputManifest)
	}
	return p
}

// checkDestinations runs before the salt or any output is created. An output
// must be absent or a regular file, and must not be the same file as an
// input, the salt, the inventory or another output: by path, through
// symlinked directories, or as a hard link.
func checkDestinations(o options) error {
	type resolved struct {
		path string
		info os.FileInfo
	}
	resolve := func(p string) (resolved, error) {
		canonical, err := canonicalPath(p)
		if err != nil {
			return resolved{}, errDestination
		}
		info, err := os.Stat(canonical)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return resolved{}, errDestination
		}
		return resolved{canonical, info}, nil
	}
	same := func(a, b resolved) bool {
		return a.path == b.path || (a.info != nil && b.info != nil && os.SameFile(a.info, b.info))
	}
	var outs, protected []resolved
	for _, p := range o.outputs() {
		info, err := os.Lstat(p)
		if err == nil && !info.Mode().IsRegular() {
			return errUnsafeDestination
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errDestination
		}
		r, err := resolve(p)
		if err != nil {
			return err
		}
		outs = append(outs, r)
	}
	for _, p := range o.protected() {
		r, err := resolve(p)
		if err != nil {
			return err
		}
		protected = append(protected, r)
	}
	for i, out := range outs {
		for _, other := range append(outs[i+1:], protected...) {
			if same(out, other) {
				return errOutputAlias
			}
		}
	}
	return nil
}

// canonicalPath resolves every symlink in p's existing directory chain; a
// missing final component keeps its name.
func canonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs, nil
	}
	resolvedParent, err := canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(abs)), nil
}

type recordPos struct{ ordinal, line int }

// inputs is everything read and validated before the salt is loaded.
type inputs struct {
	findings    []alert.AuditEvent
	actions     []actionlog.Record
	actionPos   []recordPos
	audits      []firewall.AuditEntry
	auditPos    []recordPos
	files       []streamFile
	inventory   *inputManifest
	inventoryID *inventoryDigest
}

func readInputs(o options) (*inputs, error) {
	in := &inputs{}
	for i, path := range o.findings {
		file, err := readStream(path, kindFindings, i+1, func(_ int, data []byte) (time.Time, error) {
			var e alert.AuditEvent
			if err := decodeStrict(data, &e); err != nil {
				return time.Time{}, err
			}
			if e.V != alert.AuditSchemaVersion {
				return time.Time{}, errRecordVersion
			}
			if e.Timestamp.IsZero() {
				return time.Time{}, errRecordTime
			}
			in.findings = append(in.findings, e)
			return e.Timestamp, nil
		})
		if err != nil {
			return nil, err
		}
		in.files = append(in.files, file)
	}
	for i, path := range o.actions {
		file, err := readStream(path, kindActions, i+1, func(line int, data []byte) (time.Time, error) {
			var r actionlog.Record
			if err := decodeStrict(data, &r); err != nil {
				return time.Time{}, err
			}
			if _, err := validateAction(r); err != nil {
				return time.Time{}, err
			}
			in.actions = append(in.actions, r)
			in.actionPos = append(in.actionPos, recordPos{i + 1, line})
			return r.Timestamp, nil
		})
		if err != nil {
			return nil, err
		}
		in.files = append(in.files, file)
	}
	for i, path := range o.firewallAudits {
		file, err := readStream(path, kindFirewall, i+1, func(line int, data []byte) (time.Time, error) {
			var e firewall.AuditEntry
			if err := decodeStrict(data, &e); err != nil {
				return time.Time{}, err
			}
			if _, _, _, err := validateFirewallAudit(e); err != nil {
				return time.Time{}, err
			}
			in.audits = append(in.audits, e)
			in.auditPos = append(in.auditPos, recordPos{i + 1, line})
			return e.Timestamp, nil
		})
		if err != nil {
			return nil, err
		}
		in.files = append(in.files, file)
	}
	if o.inputManifest != "" {
		if err := in.readInventory(o.inputManifest); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func (in *inputs) readInventory(path string) error {
	fail := func(code error) error { return inputError{kindInputManifest, 1, 0, code} }
	f, err := os.Open(path) // #nosec G304 -- operator-chosen inventory file
	if err != nil {
		return fail(errInputOpen)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxLineBytes+1))
	if err != nil {
		return fail(errInputRead)
	}
	if len(data) > maxLineBytes {
		return fail(errLineTooLong)
	}
	var inv inputManifest
	if err := decodeStrict(bytes.TrimSpace(data), &inv); err != nil {
		return fail(err)
	}
	sum := sha256.Sum256(data)
	in.inventory = &inv
	in.inventoryID = &inventoryDigest{SHA256: hex.EncodeToString(sum[:]), Records: len(inv.Streams)}
	return nil
}

// readStream reads one input to its end, hashing exactly the bytes read from
// disk, compressed or not, and passes every non-blank line to visit. Reading
// through EOF is what surfaces a bad gzip checksum or trailer; the gzip
// reader reads further members until the file ends, so the digest covers the
// whole file.
func readStream(path string, kind streamKind, ordinal int, visit func(line int, data []byte) (time.Time, error)) (streamFile, error) {
	fail := func(line int, code error) (streamFile, error) {
		return streamFile{}, inputError{kind, ordinal, line, code}
	}
	f, err := os.Open(path) // #nosec G304 -- operator-chosen input file
	if err != nil {
		return fail(0, errInputOpen)
	}
	defer f.Close()
	h := sha256.New()
	raw := io.TeeReader(f, h)
	r := raw
	compressed := strings.HasSuffix(path, ".gz")
	if compressed {
		zr, err := gzip.NewReader(raw)
		if err != nil {
			return fail(0, errInputGzip)
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	file := streamFile{Kind: kind, Ordinal: ordinal}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), maxLineBytes+1)
	line := 0
	for sc.Scan() {
		line++
		data := bytes.TrimSpace(sc.Bytes())
		if len(data) == 0 {
			continue
		}
		ts, err := visit(line, data)
		if err != nil {
			return fail(line, err)
		}
		file.Records++
		file.observe(ts)
	}
	if err := sc.Err(); err != nil {
		switch {
		case errors.Is(err, bufio.ErrTooLong):
			return fail(line+1, errLineTooLong)
		case compressed:
			return fail(0, errInputGzip)
		}
		return fail(0, errInputRead)
	}
	file.SHA256 = hex.EncodeToString(h.Sum(nil))
	return file, nil
}

type transformed struct {
	findings []alert.AuditEvent
	actions  []anonAction
	audits   []anonFirewallAudit
}

// transform learns every identity in every stream first, so free text in one
// stream is scrubbed of names only another stream carries, then transforms
// and verifies all rows. Verification never calls a transform.
func (r *anonymizeRun) transform(a *Anonymizer, in *inputs) (*transformed, error) {
	a.Learn(in.findings)
	a.LearnActions(in.actions)
	for i := range in.findings {
		a.learnRawID(in.findings[i].FindingID)
	}
	out := &transformed{}
	for _, e := range in.findings {
		out.findings = append(out.findings, r.event(a, e))
	}
	for i, rec := range in.actions {
		row, err := r.action(a, rec)
		if err != nil {
			return nil, inputError{kindActions, in.actionPos[i].ordinal, in.actionPos[i].line, err}
		}
		out.actions = append(out.actions, row)
	}
	for i, e := range in.audits {
		row, err := r.firewall(a, e)
		if err != nil {
			return nil, inputError{kindFirewall, in.auditPos[i].ordinal, in.auditPos[i].line, err}
		}
		out.audits = append(out.audits, row)
	}
	leaks := len(a.Verify(out.findings))
	for _, row := range out.actions {
		if a.VerifyAction(row) != nil {
			leaks++
		}
	}
	for _, row := range out.audits {
		if a.VerifyFirewallAudit(row) != nil {
			leaks++
		}
	}
	if leaks > 0 {
		return nil, fmt.Errorf("%w (%d rows)", errLeak, leaks)
	}
	return out, nil
}

func (r *anonymizeRun) execute(args []string, stdout io.Writer) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	if err = checkDestinations(o); err != nil {
		return err
	}
	var tool toolRevision
	if o.manifest != "" {
		if tool = r.revision(); !tool.clean() {
			return errRevision
		}
	}
	in, err := readInputs(o)
	if err != nil {
		return err
	}
	supplied := map[streamKind]bool{kindActions: len(o.actions) > 0, kindFirewall: len(o.firewallAudits) > 0}
	cov, err := coverage(in.files, supplied, in.inventory)
	if err != nil {
		return err
	}
	salt, err := loadOrCreateSalt(o.saltPath)
	if err != nil {
		var fixed cliError
		if errors.As(err, &fixed) {
			return fixed
		}
		return errSaltLoad
	}
	a := NewAnonymizer(salt)
	out, err := r.transform(a, in)
	if err != nil {
		return err
	}
	staged, err := r.stage(o, in, out, cov, tool, a, salt)
	if err != nil {
		return err
	}
	if err := publishOutputs(r.ops, staged); err != nil {
		return err
	}
	writeSummary(stdout, o, out, a, salt)
	return nil
}

// stage writes every output to a staged file before any is published. The
// manifest records the digests of the staged bytes, then is staged last.
func (r *anonymizeRun) stage(o options, in *inputs, out *transformed, cov map[string]string, tool toolRevision, a *Anonymizer, salt []byte) ([]stagedOutput, error) {
	var staged []stagedOutput
	var files []streamFile
	fail := func(err error) ([]stagedOutput, error) {
		for _, s := range staged {
			_ = r.ops.remove(s.temp)
		}
		return nil, err
	}
	add := func(kind streamKind, path string, encode func(io.Writer) error, times []time.Time) error {
		s, err := stageOutput(r.ops, path, encode)
		if err != nil {
			return err
		}
		staged = append(staged, s)
		f := streamFile{Kind: kind, Ordinal: 1, SHA256: s.digest, Records: len(times)}
		for _, ts := range times {
			f.observe(ts)
		}
		files = append(files, f)
		return nil
	}
	if err := add(kindFindings, o.out, func(w io.Writer) error { return encodeRows(w, out.findings) }, eventTimes(out.findings)); err != nil {
		return fail(err)
	}
	if o.actionsOut != "" {
		times := make([]time.Time, len(out.actions))
		for i := range out.actions {
			times[i] = out.actions[i].Timestamp
		}
		if err := add(kindActions, o.actionsOut, func(w io.Writer) error { return encodeRows(w, out.actions) }, times); err != nil {
			return fail(err)
		}
	}
	if o.firewallOut != "" {
		times := make([]time.Time, len(out.audits))
		for i := range out.audits {
			times[i] = out.audits[i].Timestamp
		}
		if err := add(kindFirewall, o.firewallOut, func(w io.Writer) error { return encodeRows(w, out.audits) }, times); err != nil {
			return fail(err)
		}
	}
	if o.manifest == "" {
		return staged, nil
	}
	join, results := joinRecords(in.findings, in.actions, in.audits)
	m := runManifest{
		FormatVersion: manifestFormatVersion, Tool: tool, SaltFingerprint: saltFingerprint(salt),
		AddressMap: "salted_not_topology_preserving", Inputs: in.files, Outputs: files, InputManifest: in.inventoryID,
		Join: join, DroppedFields: a.Dropped(), ActionResults: results, Coverage: cov,
	}
	s, err := stageOutput(r.ops, o.manifest, func(w io.Writer) error {
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(append(raw, '\n'))
		return err
	})
	if err != nil {
		return fail(err)
	}
	return append(staged, s), nil
}

func eventTimes(events []alert.AuditEvent) []time.Time {
	times := make([]time.Time, len(events))
	for i := range events {
		times[i] = events[i].Timestamp
	}
	return times
}

func saltFingerprint(salt []byte) string {
	sum := sha256.Sum256(salt)
	return hex.EncodeToString(sum[:6])
}

func loadOrCreateSalt(path string) ([]byte, error) {
	salt, err := readSalt(path)
	if !errors.Is(err, os.ErrNotExist) {
		return salt, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	salt = make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return nil, err
	}
	// Exclusive creation cannot truncate a salt created by another process
	// between the read and the write, or follow a newly installed symlink.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- operator-chosen salt path
	if errors.Is(err, os.ErrExist) {
		return readSalt(path)
	}
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(salt)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, err
	}
	return salt, nil
}

func readSalt(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-chosen salt path; symlinks refused
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errSaltUnsafe
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(b) < 32 {
		return nil, errSaltShort
	}
	return b, nil
}

// writeSummary prints counts only. Check names come from the input, so the
// summary counts them rather than listing them.
func writeSummary(w io.Writer, o options, out *transformed, a *Anonymizer, salt []byte) {
	fmt.Fprintln(w, "output: written")
	fmt.Fprintf(w, "events: %d\n", len(out.findings))
	if o.actionsOut != "" {
		fmt.Fprintf(w, "action rows: %d\n", len(out.actions))
	}
	if o.firewallOut != "" {
		fmt.Fprintf(w, "firewall rows: %d\n", len(out.audits))
	}
	if len(out.findings) > 0 {
		first, last := out.findings[0].Timestamp, out.findings[0].Timestamp
		for i := range out.findings {
			if out.findings[i].Timestamp.Before(first) {
				first = out.findings[i].Timestamp
			}
			if out.findings[i].Timestamp.After(last) {
				last = out.findings[i].Timestamp
			}
		}
		fmt.Fprintf(w, "span: %s .. %s\n", first.UTC().Format("2006-01-02T15:04:05Z"), last.UTC().Format("2006-01-02T15:04:05Z"))
	}
	counts := a.Counts()
	for _, k := range sortedKeys(counts) {
		fmt.Fprintf(w, "replaced %s: %d\n", k, counts[k])
	}
	fmt.Fprintln(w, "leak check: clean")
	fmt.Fprintf(w, "salt fingerprint: %s\n", saltFingerprint(salt))
	checks := map[string]bool{}
	for i := range out.findings {
		checks[out.findings[i].Check] = true
	}
	fmt.Fprintf(w, "checks: %d distinct\n", len(checks))
	if o.manifest != "" {
		fmt.Fprintln(w, "manifest: written")
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }
