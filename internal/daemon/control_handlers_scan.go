package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/store"
)

// handleScanEnqueue validates the request and submits a new full-scan job to
// the ScanJobManager. Scope="account" scans a single account; Scope="all"
// enqueues a server-wide scan. The control payload is translated into
// checks.AccountScanOptions with the full-scan option set (MaxFiles=0,
// ForceContent=true, ForceFileIndex=true).
func (c *ControlListener) handleScanEnqueue(argsRaw json.RawMessage) (any, error) {
	if c.scanJobs == nil {
		return nil, fmt.Errorf("scan job manager not available")
	}

	var req control.ScanEnqueueRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	cfg := c.d.currentCfg()
	opts := checks.AccountScanOptions{
		MaxFiles:       0,
		ForceContent:   true,
		ForceFileIndex: true,
		RespectIgnores: req.RespectIgnores,
		MaxFileBytes:   checks.FullScanMaxFileBytes(cfg),
	}

	switch req.Scope {
	case "account":
		if req.Target == "" {
			return nil, fmt.Errorf("target is required")
		}
		if !control.ValidScanAccountTarget(req.Target) {
			return nil, fmt.Errorf("invalid account target %q", req.Target)
		}
		id, err := c.scanJobs.Enqueue("account", req.Target, opts, req.Quarantine)
		if err != nil {
			return nil, fmt.Errorf("enqueue: %w", err)
		}
		return control.ScanEnqueueResponse{JobID: id, State: "queued"}, nil

	case "all":
		// Target must be empty or the literal "all"; it must not look like an
		// account name or path component — the daemon normalises it to "all".
		if req.Target != "" && req.Target != "all" {
			return nil, fmt.Errorf("invalid target %q for scope \"all\": must be empty or \"all\"", req.Target)
		}
		id, err := c.scanJobs.Enqueue("all", "all", opts, req.Quarantine)
		if err != nil {
			return nil, fmt.Errorf("enqueue: %w", err)
		}
		return control.ScanEnqueueResponse{JobID: id, State: "queued"}, nil

	default:
		return nil, fmt.Errorf("unsupported scope %q: must be \"account\" or \"all\"", req.Scope)
	}
}

// handleScanStatus returns the status of one job (when JobID is set) or the
// full list of jobs ordered newest-first. Unknown IDs produce an error.
func (c *ControlListener) handleScanStatus(argsRaw json.RawMessage) (any, error) {
	if c.scanJobs == nil {
		return nil, fmt.Errorf("scan job manager not available")
	}

	var req control.ScanStatusRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	if req.JobID != "" {
		rec, ok := c.scanJobs.Progress(req.JobID)
		if !ok {
			return nil, fmt.Errorf("job not found: %q", req.JobID)
		}
		return control.ScanStatusResponse{Job: &rec}, nil
	}

	jobs, err := c.scanJobs.ListJobs()
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	if jobs == nil {
		jobs = []store.ScanJobRecord{}
	}
	return control.ScanStatusResponse{Jobs: jobs}, nil
}

// handleScanReport returns the job record plus a paginated slice of its
// findings. JobID is required; Offset and Limit follow the usual page semantics
// (Limit=0 returns all findings).
func (c *ControlListener) handleScanReport(argsRaw json.RawMessage) (any, error) {
	if c.scanJobs == nil {
		return nil, fmt.Errorf("scan job manager not available")
	}

	var req control.ScanReportRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	if req.JobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	rec, ok := c.scanJobs.Progress(req.JobID)
	if !ok {
		return nil, fmt.Errorf("job not found: %q", req.JobID)
	}

	if req.Offset < 0 {
		req.Offset = 0
	}

	findings, total, err := c.scanJobs.ListFindings(req.JobID, req.Offset, req.Limit)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	if findings == nil {
		findings = []alert.Finding{}
	}

	return control.ScanReportResponse{
		Job:      rec,
		Findings: findings,
		Total:    total,
	}, nil
}

// handleScanCancel cancels the job with the given ID. If the job is queued it
// will be marked canceled before the worker processes it; if it is running its
// context is canceled and partial findings are retained. Unknown or already
// terminal IDs produce an error.
func (c *ControlListener) handleScanCancel(argsRaw json.RawMessage) (any, error) {
	if c.scanJobs == nil {
		return nil, fmt.Errorf("scan job manager not available")
	}

	var req control.ScanCancelRequest
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &req); err != nil {
			return nil, fmt.Errorf("parsing args: %w", err)
		}
	}

	if req.JobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	if err := c.scanJobs.Cancel(req.JobID); err != nil {
		return nil, fmt.Errorf("cancel: %w", err)
	}

	// Return the job's current state. The worker may not have transitioned it
	// yet; the caller polls via scan.status for the terminal state.
	rec, ok := c.scanJobs.Progress(req.JobID)
	state := "canceling"
	if ok {
		state = rec.State
	}

	return control.ScanCancelResponse{JobID: req.JobID, State: state}, nil
}
