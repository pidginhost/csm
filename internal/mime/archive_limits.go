package mime

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/zipdir"
)

var errArchiveWalk = errors.New("archive walk limit exceeded")

func validateZIPDirectoryEntry(file *zip.File) error {
	if file.UncompressedSize64 != 0 {
		return zip.ErrFormat
	}
	if file.CompressedSize64 == 0 {
		return nil
	}
	// Some writers deflate empty directories. File.Open otherwise bypasses
	// their decompressor, so validate their claimed empty content as a file.
	entry := *file
	entry.Name = strings.TrimRight(entry.Name, "/")
	rc, err := entry.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	var probe [1]byte
	n, err := io.ReadFull(rc, probe[:])
	if n == 0 && err == io.EOF {
		return nil
	}
	return zip.ErrFormat
}

// validateZIPDirectory checks the actual listing before archive/zip allocates
// File objects. Its end record count is only a hint, even for ZIP64 archives.
func validateZIPDirectory(r io.ReaderAt, size int64, dir zipdir.Directory, walkCap int) error {
	maxRecords := uint64(max(walkCap, 0)) // #nosec G115 -- clamped to nonnegative.
	if dir.Records > maxRecords {
		return errArchiveWalk
	}
	// archive/zip accepts a shorter comment than zipdir.Read does. A second
	// end record inside the comment must not select an unchecked directory.
	tail := make([]byte, size-dir.EndOffset)
	if _, err := r.ReadAt(tail, dir.EndOffset); err != nil {
		return err
	}
	for i := len(tail) - zipdir.EndLen; i > 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == zipdir.EndSignature {
			return zipdir.ErrFormat
		}
	}
	// archive/zip may fall back to the declared offset when the computed
	// base is positive. Do not let it read an unchecked earlier listing.
	if dir.DeclaredOffset < dir.Offset {
		var sig [4]byte
		if _, err := r.ReadAt(sig[:], dir.DeclaredOffset); err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(sig[:]) == zipdir.HeaderSignature {
			return zipdir.ErrFormat
		}
	}
	var header [zipdir.HeaderLen]byte
	offset, remaining := dir.Offset, dir.Size
	var records uint64
	for remaining > 0 {
		if records >= maxRecords {
			return errArchiveWalk
		}
		if remaining < int64(len(header)) {
			return zipdir.ErrFormat
		}
		if _, err := r.ReadAt(header[:], offset); err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(header[:]) != zipdir.HeaderSignature {
			return zipdir.ErrFormat
		}
		n := int64(len(header)) + int64(binary.LittleEndian.Uint16(header[28:30])) +
			int64(binary.LittleEndian.Uint16(header[30:32])) + int64(binary.LittleEndian.Uint16(header[32:34]))
		if n > remaining {
			return zipdir.ErrFormat
		}
		offset += n
		remaining -= n
		records++
	}
	if records != dir.Records {
		return zipdir.ErrFormat
	}
	return nil
}

const tarBlockSize = 512

// gzipStreamReader preserves concatenated gzip streams while bounding empty
// streams, which can consume work without yielding any decompressed bytes.
type gzipStreamReader struct {
	compressed *bufio.Reader
	gr         *gzip.Reader
	walkCap    int
	streams    int
	ended      bool
}

func (r *gzipStreamReader) Read(p []byte) (int, error) {
	for {
		if r.ended {
			if _, err := r.compressed.Peek(1); err != nil {
				return 0, err
			}
			if r.streams >= r.walkCap {
				return 0, errArchiveWalk
			}
			if err := r.gr.Reset(r.compressed); err != nil {
				return 0, err
			}
			r.gr.Multistream(false)
			r.streams++
			r.ended = false
		}
		n, err := r.gr.Read(p)
		if err == io.EOF {
			r.ended = true
			if n == 0 {
				continue
			}
			err = nil
		}
		return n, err
	}
}

// tarWalkReader counts physical headers, including the PAX and GNU metadata
// that tar.Reader.Next consumes internally. tar.Reader still owns validation
// and metadata interpretation. After Next, setMember supplies the effective
// payload size, which can differ from the raw header size in PAX archives.
type tarWalkReader struct {
	r         io.Reader
	walkCap   int
	walked    int
	header    [tarBlockSize]byte
	pending   []byte
	remaining int64 // -1 passes reads through while Next resolves a file header
	padding   int64
	mapBytes  int64 // sparse-map bytes consumed by Next after the file header
}

func (r *tarWalkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.remaining < 0 {
		n, err := r.r.Read(p)
		r.mapBytes += int64(n)
		return n, err
	}
	if r.remaining > 0 || r.padding > 0 {
		left := &r.remaining
		if *left == 0 {
			left = &r.padding
		}
		if int64(len(p)) > *left {
			p = p[:*left]
		}
		n, err := r.r.Read(p)
		*left -= int64(n)
		return n, err
	}
	if _, err := io.ReadFull(r.r, r.header[:]); err != nil {
		return 0, err
	}
	if r.header != [tarBlockSize]byte{} {
		if r.walked >= r.walkCap {
			return 0, errArchiveWalk
		}
		r.walked++
		switch r.header[156] {
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			n, err := tarMetadataSize(r.header[124:136])
			if err != nil {
				return 0, err
			}
			r.remaining, r.padding = n, (tarBlockSize-n%tarBlockSize)%tarBlockSize
		case tar.TypeGNUSparse:
			// The extractor does not scan legacy sparse members. Reject them
			// before Next can walk an unchecked chain of extension headers.
			return 0, errors.New("unsupported sparse tar member")
		default:
			r.remaining = -1
			r.mapBytes = 0
		}
	}
	r.pending = r.header[:]
	return r.Read(p)
}

func (r *tarWalkReader) setMember(hdr *tar.Header) error {
	n := hdr.Size
	for key := range hdr.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			// Next replaces Size with the logical sparse size. The wire still
			// carries the physical size, possibly overridden by PAX "size".
			var err error
			n, err = tarMetadataSize(r.header[124:136])
			if size := hdr.PAXRecords["size"]; size != "" {
				n, err = strconv.ParseInt(size, 10, 64)
			}
			if err != nil {
				return err
			}
			break
		}
	}
	switch hdr.Typeflag {
	case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
		n = 0
	case tar.TypeXGlobalHeader:
		// Next has consumed the metadata body but its padding remains.
		return nil
	}
	r.remaining, r.padding = n-r.mapBytes, (tarBlockSize-n%tarBlockSize)%tarBlockSize
	return nil
}

func tarMetadataSize(field []byte) (int64, error) {
	if field[0]&0x80 != 0 {
		// GNU base-256 numbers are signed. Sizes must be nonnegative and fit
		// int64, so the high marker and leading padding are the only high bits.
		if field[0] != 0x80 || !bytes.Equal(field[1:4], []byte{0, 0, 0}) {
			return 0, tar.ErrHeader
		}
		n := binary.BigEndian.Uint64(field[4:])
		if n > 1<<63-1 {
			return 0, tar.ErrHeader
		}
		return int64(n), nil // #nosec G115 -- bounded by MaxInt64 above.
	}
	s := strings.Trim(string(field), " \x00")
	if s == "" {
		return 0, nil
	}
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.ParseUint(s, 8, 63)
	if err != nil {
		return 0, tar.ErrHeader
	}
	return int64(n), nil // #nosec G115 -- ParseUint is limited to 63 bits.
}

// finishTar verifies the gzip trailer and permits only tar's zero padding
// after its end marker. Another archive or nonzero payload was not scanned.
func finishTar(b *budgetReader) error {
	var buf [32 << 10]byte
	for {
		n, err := b.Read(buf[:])
		if b.err != nil {
			return b.err
		}
		for _, v := range buf[:n] {
			if v != 0 {
				return errors.New("unread data after tar end marker")
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}
