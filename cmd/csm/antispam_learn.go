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
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/control"
)

// antispamEUID reads the effective uid; tests replace it.
var antispamEUID = os.Geteuid

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

--spam    learn each file as spam with one operator mark per matched cluster
--forget  remove the learned clusters each file matches

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
		case "--spam", "--forget":
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
	if action == "" || len(files) == 0 {
		_, _ = fmt.Fprint(errOut, learnUsage)
		return 2
	}
	if antispamEUID() != 0 {
		fmt.Fprintln(errOut, "csm: antispam learn must run as root")
		return 1
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
	fmt.Fprintf(out, "%s: request %s\n", name, args.RequestID)
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
	fmt.Fprintf(out, "%s: %s\n", name, res.Outcome)
	return res.ExitOK
}

// readLearnFile reads an operator file under the same rules as a watched
// candidate (spec 7.1): a regular file, never a symlink, with one link,
// within the size limit, unchanged while it is read.
func readLearnFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("not a regular file (symlinks are refused)")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- an operator-named file, checked below
	if err != nil {
		return nil, errors.New("cannot open the file")
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("the file changed while it was opened")
	}
	if st, ok := opened.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		return nil, errors.New("the file has more than one link; copy it first")
	}
	if opened.Size() > learn.MaxBody {
		return nil, fmt.Errorf("the file is larger than %d MiB", learn.MaxBody>>20)
	}
	data, err := io.ReadAll(io.LimitReader(f, learn.MaxBody+1))
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	after, err := f.Stat()
	if err != nil || int64(len(data)) != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("the file changed while it was read")
	}
	return data, nil
}
