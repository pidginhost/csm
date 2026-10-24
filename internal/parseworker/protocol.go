// Package parseworker runs archive parsing on tenant files in a worker
// process. The worker gets a descriptor, never a path, and answers with the
// archive's entry names; classification stays in the daemon.
package parseworker

import (
	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/workerproc"
)

// ProtocolVersion changes whenever a request or reply changes shape.
const ProtocolVersion = 2

// OpListZip lists a zip's central directory. The request carries the zip as
// its one descriptor; the reply carries the listing as a memfd of records
// (see writeEntry), sealed against writes, growth and shrinkage, or an
// Incomplete reason and no descriptor.
const OpListZip = "list_zip"

// ListZipArgs is the list_zip payload.
type ListZipArgs struct {
	MaxDirBytes uint64 `json:"max_dir_bytes"`
}

// ListZipResult is the list_zip reply. Entries is required, and must be zero
// when Incomplete reports that no listing is being returned.
type ListZipResult struct {
	Entries    uint64 `json:"entries"`
	Incomplete string `json:"incomplete,omitempty"`
}

// maxIncomplete caps the reason a worker reports for a partial listing.
const maxIncomplete = 512

// OpExtractMessage extracts a message's attachments. The request carries
// the spool -H and -D files as its two descriptors; the reply carries one
// sealed memfd per part, in the order of ExtractResult.Parts.
const OpExtractMessage = "extract_message"

// MaxParts is the most parts one reply carries: each is a descriptor, and
// a frame and the worker unit both bound how many there can be.
const MaxParts = emime.MaxParts

// MaxEncryptedEntries bounds the encrypted archive members a reply names;
// the rest are only counted, as max_archive_files can be set far higher.
const MaxEncryptedEntries = 100

// Caps on strings a reply carries, in bytes.
const (
	maxNameBytes   = 255
	maxHeaderBytes = 998 // RFC 5322 line length
	maxRecipients  = 100
)

// ExtractArgs are the request's limits. It carries no path: the worker only
// ever reads the descriptors it is given.
type ExtractArgs struct {
	MaxAttachmentSize int64 `json:"max_attachment_size"`
	MaxArchiveDepth   int   `json:"max_archive_depth"`
	MaxArchiveFiles   int   `json:"max_archive_files"`
	MaxExtractionSize int64 `json:"max_extraction_size"`
}

// ExtractPart describes one part; its bytes are the matching descriptor.
type ExtractPart struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Nested      bool   `json:"nested,omitempty"`
	ArchiveName string `json:"archive_name,omitempty"`
}

// EncryptedEntry names an archive member that could not be read.
type EncryptedEntry struct {
	ArchiveName string `json:"archive_name"`
	Filename    string `json:"filename"`
}

// ExtractResult is the extract_message reply.
type ExtractResult struct {
	Parts                   []ExtractPart    `json:"parts"`
	Partial                 bool             `json:"partial,omitempty"`
	PartialReason           string           `json:"partial_reason,omitempty"`
	EncryptedEntries        []EncryptedEntry `json:"encrypted_entries,omitempty"`
	EncryptedEntriesOmitted int              `json:"encrypted_entries_omitted,omitempty"`
	Direction               string           `json:"direction,omitempty"`
	From                    string           `json:"from,omitempty"`
	To                      []string         `json:"to,omitempty"`
	Subject                 string           `json:"subject,omitempty"`
}

// WorkerLimits is what the worker accepts: at most two request descriptors.
// Its frame cap also bounds the replies it sends.
var WorkerLimits = workerproc.Limits{MaxFrameBytes: 1 << 20, MaxFDs: 2}

// ExtractLimits is what the daemon accepts back from extract_message.
var ExtractLimits = workerproc.Limits{MaxFrameBytes: 1 << 20, MaxFDs: MaxParts}

// Limits bounds frames both ways: one descriptor, small JSON.
var Limits = workerproc.Limits{MaxFrameBytes: 64 << 10, MaxFDs: 1}
