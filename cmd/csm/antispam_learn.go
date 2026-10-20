package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/safepath"
)

// antispamEUID reads the effective uid; tests replace it.
var antispamEUID = os.Geteuid

var learnReadAll = io.ReadAll

// learnTimeout bounds one file's request; the daemon gives up first and
// keeps the outcome under the printed request ID.
const learnTimeout = 5 * time.Minute

var errLearnTransport = errors.New("lost the daemon's reply")

// learnSend submits one file; tests replace it.
var learnSend = func(args control.AntispamLearnArgs) (json.RawMessage, error) {
	raw, err := sendControlWithTimeout(control.CmdAntispamLearn, args, learnTimeout)
	var lost transportError
	if errors.As(err, &lost) {
		return nil, fmt.Errorf("%w: %w", errLearnTransport, err)
	}
	return raw, err
}

const learnUsage = `Usage: csm antispam learn --spam <file>...
       csm antispam learn --forget <file>...
       csm antispam learn --status [<request-id>...]
       csm antispam learn --fresh-namespace

--spam    learn each file as spam with one operator mark per matched cluster
--forget  remove the learned clusters each file matches
--status  show what the daemon recorded for request IDs, or list the
          requests that are still pending
--fresh-namespace
          with learning disabled, move the learning keys and stored
          messages aside and empty the learning state; the next enable
          starts a new, empty namespace

Runs as root against the running daemon with antispam learning enabled.
Each file gets a request ID, printed before it is sent; the daemon keeps
the outcome under that ID. Exit status is 0 only when every file was fully
learned, already learned, forgotten or matched nothing.
`

func runAntispam() {
	args := os.Args[2:]
	if len(args) == 0 || args[0] != "learn" {
		fmt.Fprint(os.Stderr, learnUsage)
		os.Exit(2)
	}
	os.Exit(antispamLearn(args[1:], os.Stdout, os.Stderr))
}

// antispamLearn runs csm antispam learn and returns the exit status.
func antispamLearn(args []string, out, errOut io.Writer) int {
	var action string
	var files []string
	for _, a := range args {
		switch a {
		case "--spam", "--forget", "--status", "--fresh-namespace":
			if action != "" {
				_, _ = fmt.Fprint(errOut, learnUsage)
				return 2
			}
			action = a[2:]
		case "-h", "--help":
			_, _ = fmt.Fprint(out, learnUsage)
			return 0
		default:
			if len(a) > 0 && a[0] == '-' {
				_, _ = fmt.Fprint(errOut, learnUsage)
				return 2
			}
			files = append(files, a)
		}
	}
	if action == "" || len(files) == 0 && action != "status" && action != "fresh-namespace" || len(files) > 0 && action == "fresh-namespace" {
		_, _ = fmt.Fprint(errOut, learnUsage)
		return 2
	}
	if antispamEUID() != 0 {
		fmt.Fprintln(errOut, "csm: antispam learn must run as root")
		return 1
	}
	switch action {
	case "status":
		return learnStatus(files, out, errOut)
	case "fresh-namespace":
		return learnFresh(out, errOut)
	}
	status := 0
	for _, path := range files {
		if !learnFile(action, path, out, errOut) {
			status = 1
		}
	}
	return status
}

// learnFile sends one file and reports its outcome; true means a zero exit
// for this file.
func learnFile(action, path string, out, errOut io.Writer) bool {
	name := strconv.Quote(filepath.Base(path))
	snapshot, err := readLearnFile(path)
	if err != nil {
		fmt.Fprintf(errOut, "csm: %s: %v\n", name, err)
		return false
	}
	var id [16]byte
	if _, randErr := rand.Read(id[:]); randErr != nil {
		fmt.Fprintf(errOut, "csm: %s: cannot create a request ID\n", name)
		return false
	}
	sum := sha256.Sum256(snapshot)
	args := control.AntispamLearnArgs{Action: action, RequestID: hex.EncodeToString(id[:]), Name: filepath.Base(path),
		SnapshotSHA: hex.EncodeToString(sum[:]), Snapshot: snapshot}
	if _, printErr := fmt.Fprintf(out, "%s: request %s\n", name, args.RequestID); printErr != nil {
		fmt.Fprintf(errOut, "csm: %s: cannot print request ID: %v\n", name, printErr)
		return false
	}
	raw, err := learnSend(args)
	if errors.Is(err, errLearnTransport) {
		// The daemon may have acted; the same ID returns what it recorded.
		raw, err = learnSend(args)
	}
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			err = errors.New("the CSM daemon is not running")
		}
		fmt.Fprintf(errOut, "csm: %s: request %s: %v\n", name, args.RequestID, err)
		return false
	}
	var res control.AntispamLearnResult
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintf(errOut, "csm: %s: request %s: unexpected daemon reply\n", name, args.RequestID)
		return false
	}
	for _, c := range res.Clusters {
		if c.ClusterID == 0 {
			fmt.Fprintf(out, "%s: part: %s\n", name, c.Result)
			continue
		}
		fmt.Fprintf(out, "%s: cluster %d: %s\n", name, c.ClusterID, c.Result)
	}
	if action == learn.ActionForget && len(res.Clusters) > 0 {
		fmt.Fprintf(out, "%s: every contributor to these clusters is affected\n", name)
	}
	if res.Outcome == learn.ResultDeferred {
		fmt.Fprintf(out, "%s: deferred: nothing changed; learning is busy, run the command again later\n", name)
		return false
	}
	fmt.Fprintf(out, "%s: %s\n", name, res.Outcome)
	return res.ExitOK
}

// readLearnFile reads an operator file under the same rules as a watched
// candidate (spec 7.1): a regular file, never a symlink, with one link,
// within the size limit, unchanged while it is read.
func readLearnFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("cannot resolve the file")
	}
	dir, err := safepath.OpenDirNoFollow(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("cannot open the parent directory without following symlinks")
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.OpenFile(filepath.Base(absolute), os.O_RDONLY, 0)
	if err != nil {
		return nil, errors.New("cannot open the file without following symlinks")
	}
	defer func() { _ = f.Close() }()
	var before, after unix.Stat_t
	// #nosec G115 -- an open descriptor fits in int on supported Unix hosts.
	fd := int(f.Fd())
	if statErr := unix.Fstat(fd, &before); statErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("not a readable regular file")
	}
	if before.Nlink != 1 {
		return nil, errors.New("the file must have exactly one link; copy it first")
	}
	if before.Size > learn.MaxBody {
		return nil, fmt.Errorf("the file is larger than %d MiB", learn.MaxBody>>20)
	}
	data, err := learnReadAll(io.LimitReader(f, learn.MaxBody+1))
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	if err := unix.Fstat(fd, &after); err != nil || int64(len(data)) != before.Size ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Uid != after.Uid || before.Gid != after.Gid ||
		before.Nlink != after.Nlink || before.Mode != after.Mode || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("the file changed while it was read")
	}
	return data, nil
}

// learnStatus prints what the daemon recorded for request IDs, or lists
// the unfinished requests when none are named.
func learnStatus(ids []string, out, errOut io.Writer) int {
	raw, err := sendControl(control.CmdAntispamLearnStatus, control.AntispamLearnStatusArgs{RequestIDs: ids})
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			err = errors.New("the CSM daemon is not running")
		}
		fmt.Fprintf(errOut, "csm: %v\n", err)
		return 1
	}
	var res control.AntispamLearnStatusResult
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintln(errOut, "csm: unexpected daemon reply")
		return 1
	}
	if len(ids) == 0 && len(res.Requests) == 0 {
		fmt.Fprintln(out, "no pending learning requests")
	}
	for _, r := range res.Requests {
		if !r.Found {
			fmt.Fprintf(out, "%s: no record\n", r.RequestID)
			continue
		}
		outcome := r.Outcome
		if outcome == "" {
			outcome = "received, nothing recorded yet"
		}
		fmt.Fprintf(out, "%s: %s %s\n", r.RequestID, r.Action, outcome)
		for _, c := range r.Clusters {
			switch {
			case c.ClusterID == 0:
				fmt.Fprintf(out, "  part: %s\n", c.Result)
			case c.Phase != "":
				fmt.Fprintf(out, "  cluster %d: %s (%s)\n", c.ClusterID, c.Result, c.Phase)
			default:
				fmt.Fprintf(out, "  cluster %d: %s\n", c.ClusterID, c.Result)
			}
		}
		for _, d := range r.Digests {
			fmt.Fprintf(out, "  digest %s\n", d)
		}
	}
	return 0
}

// learnFreshSend asks the daemon for a fresh namespace; tests replace it.
var learnFreshSend = func() (json.RawMessage, error) {
	return sendControl(control.CmdAntispamLearnFresh, nil)
}

// learnFresh runs csm antispam learn --fresh-namespace.
func learnFresh(out, errOut io.Writer) int {
	raw, err := learnFreshSend()
	if err != nil {
		if errors.Is(err, errDaemonNotRunning) {
			err = errors.New("the CSM daemon is not running")
		}
		fmt.Fprintf(errOut, "csm: %v\n", err)
		return 1
	}
	var res control.AntispamLearnFreshResult
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintln(errOut, "csm: unexpected daemon reply")
		return 1
	}
	if res.Archived != "" {
		fmt.Fprintf(out, "previous learning keys and stored messages moved to %s; remove it once its retention is no longer needed\n", res.Archived)
	}
	fmt.Fprintln(out, "learning state emptied; the next enable creates new keys and a new namespace")
	return 0
}
