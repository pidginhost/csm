package parseworker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/pidginhost/csm/internal/zipdir"
)

// ListEntries walks a zip's central directory and calls visit for each entry
// in order. Errors, visit's included, come back as is.
func ListEntries(ctx context.Context, r io.ReaderAt, size int64, maxDirBytes uint64, visit func(name string, dir bool) error) error {
	dir, err := zipdir.Read(r, size, maxDirBytes)
	if err != nil {
		return err
	}
	return zipdir.Walk(ctx, r, dir, func(e zipdir.Entry) error {
		return visit(e.Name, e.Mode().IsDir())
	})
}

// A listing record is one flag byte (bit 0: directory; any other bit is
// invalid), a 2-byte big-endian name length, and the name.
const flagDir = 1

func writeEntry(w io.Writer, name string, dir bool) error {
	if len(name) > math.MaxUint16 {
		return fmt.Errorf("parseworker: entry name of %d bytes exceeds %d", len(name), math.MaxUint16)
	}
	var head [3]byte
	if dir {
		head[0] = flagDir
	}
	binary.BigEndian.PutUint16(head[1:], uint16(len(name))) // #nosec G115 -- bounded above.
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, name)
	return err
}

// readEntries decodes records until a clean end of input and returns how
// many it read. A short record or an unknown flag bit is an error; a visit
// error stops the read and is returned unwrapped. maxDirBytes is the original
// request's directory budget, never a size supplied by the worker. The caller
// must provide a reader over the listing file, not a potentially blocking pipe.
func readEntries(ctx context.Context, r io.Reader, maxDirBytes uint64, visit func(name string, dir bool) error) (uint64, error) {
	br := bufio.NewReader(r)
	var n uint64
	var head [3]byte
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if _, err := io.ReadFull(br, head[:1]); err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, fmt.Errorf("parseworker: listing record %d: %w", n, err)
		}
		if head[0]&^flagDir != 0 {
			return n, fmt.Errorf("parseworker: listing record %d has flags %#x", n, head[0])
		}
		if _, err := io.ReadFull(br, head[1:]); err != nil {
			return n, fmt.Errorf("parseworker: listing record %d truncated: %w", n, noEOF(err))
		}
		nameLen := binary.BigEndian.Uint16(head[1:])
		// Each record costs at least a central-directory header and its name.
		// Charging that overhead also bounds floods of empty names from a
		// compromised worker without rejecting any valid directory in budget.
		cost := uint64(zipdir.HeaderLen) + uint64(nameLen)
		if cost > maxDirBytes {
			return n, fmt.Errorf("parseworker: listing record %d: %w", n, zipdir.ErrScanLimit)
		}
		maxDirBytes -= cost
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(br, name); err != nil {
			return n, fmt.Errorf("parseworker: listing record %d truncated: %w", n, noEOF(err))
		}
		n++
		if err := visit(string(name), head[0]&flagDir != 0); err != nil {
			return n, err
		}
	}
}

func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
