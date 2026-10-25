//go:build linux

package parseworker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/workerproc"
)

// Serve answers parse requests on conn until the daemon closes it.
func Serve(ctx context.Context, conn *net.UnixConn) error {
	return workerproc.Serve(ctx, conn, WorkerLimits, handle)
}

func handle(ctx context.Context, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
	switch req.Op {
	case workerproc.OpHello:
		return workerproc.HelloReply(ProtocolVersion), nil
	case OpListZip:
		return listZip(ctx, req, fds)
	case OpExtractMessage:
		return extractMessage(req, fds)
	default:
		return workerproc.Frame{Error: fmt.Sprintf("unknown op %q", req.Op)}, nil
	}
}

func listZip(ctx context.Context, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
	if len(fds) != 1 {
		return workerproc.Frame{Error: fmt.Sprintf("list_zip takes one descriptor, got %d", len(fds))}, nil
	}
	var args ListZipArgs
	dec := json.NewDecoder(bytes.NewReader(req.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&args); err != nil {
		return workerproc.Frame{Error: fmt.Sprintf("list_zip arguments: %v", err)}, nil
	}
	st, err := fds[0].Stat()
	if err != nil {
		return workerproc.Frame{Error: err.Error()}, nil
	}
	if !st.Mode().IsRegular() {
		return workerproc.Frame{Error: "list_zip descriptor is not a regular file"}, nil
	}
	fd, err := unix.MemfdCreate("csm-zip-listing", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return workerproc.Frame{Error: fmt.Sprintf("memfd: %v", err)}, nil
	}
	listing := os.NewFile(uintptr(fd), "csm-zip-listing")
	w := bufio.NewWriterSize(listing, 64<<10)
	var n uint64
	err = ListEntries(ctx, fds[0], st.Size(), args.MaxDirBytes, func(name string, dir bool) error {
		n++
		return writeEntry(w, name, dir)
	})
	if err == nil {
		err = w.Flush()
	}
	if err != nil {
		_ = listing.Close()
		reason := err.Error()
		if len(reason) > maxIncomplete {
			reason = reason[:maxIncomplete]
		}
		return result(ListZipResult{Incomplete: reason}), nil
	}
	if _, err := unix.FcntlInt(listing.Fd(), unix.F_ADD_SEALS, listingSeals); err != nil {
		_ = listing.Close()
		return workerproc.Frame{Error: fmt.Sprintf("seal listing: %v", err)}, nil
	}
	return result(ListZipResult{Entries: n}), []*os.File{listing}
}

func result(r ListZipResult) workerproc.Frame {
	payload, _ := json.Marshal(r) // A number and a string cannot fail to marshal.
	return workerproc.Frame{Payload: payload}
}
