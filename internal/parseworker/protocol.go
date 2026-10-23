// Package parseworker runs archive parsing on tenant files in a worker
// process. The worker gets a descriptor, never a path, and answers with the
// archive's entry names; classification stays in the daemon.
package parseworker

import "github.com/pidginhost/csm/internal/workerproc"

// ProtocolVersion changes whenever a request or reply changes shape.
const ProtocolVersion = 1

// OpListZip lists a zip's central directory. The request carries the zip as
// its one descriptor; the reply carries the listing as a memfd of records
// (see writeEntry), or an Incomplete reason and no descriptor.
const OpListZip = "list_zip"

// ListZipArgs is the list_zip payload.
type ListZipArgs struct {
	MaxDirBytes uint64 `json:"max_dir_bytes"`
}

// ListZipResult is the list_zip reply.
type ListZipResult struct {
	Entries    uint64 `json:"entries"`
	Incomplete string `json:"incomplete,omitempty"`
}

// maxIncomplete caps the reason a worker reports for a partial listing.
const maxIncomplete = 512

// Limits bounds frames both ways: one descriptor, small JSON.
var Limits = workerproc.Limits{MaxFrameBytes: 64 << 10, MaxFDs: 1}
