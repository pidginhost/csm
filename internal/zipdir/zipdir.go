// Package zipdir locates a zip archive's central directory from its
// end-of-central-directory record, zip64 included, without reading any entry
// data. Callers use the record count and directory size to refuse an archive
// before allocating per-entry metadata for it.
package zipdir

import (
	"encoding/binary"
	"errors"
	"io"
)

// Record layout constants from APPNOTE.TXT.
const (
	HeaderLen        = 46
	EndLen           = 22
	End64Len         = 56
	End64LocatorLen  = 20
	MaxCommentLen    = 1<<16 - 1
	HeaderSignature  = 0x02014b50
	EndSignature     = 0x06054b50
	End64Signature   = 0x06064b50
	End64LocatorSign = 0x07064b50
)

var (
	ErrFormat    = errors.New("invalid zip central directory")
	ErrScanLimit = errors.New("zip central directory exceeds scan limit")
)

// Directory locates a zip's central directory.
type Directory struct {
	Offset  int64
	Size    int64
	Records uint64
}

// Read finds the end-of-central-directory record (zip64 included) and
// returns where the directory is and how many records it claims. A directory
// larger than maxDirBytes is ErrScanLimit. Nothing is decompressed and only
// the tail and the zip64 records are read.
func Read(r io.ReaderAt, size int64, maxDirBytes uint64) (Directory, error) {
	if size < EndLen {
		return Directory{}, ErrFormat
	}
	tailLen := int64(EndLen + MaxCommentLen)
	if tailLen > size {
		tailLen = size
	}
	tail := make([]byte, int(tailLen))
	if err := readAtFull(r, tail, size-tailLen); err != nil {
		return Directory{}, err
	}

	endIndex := findEnd(tail)
	if endIndex < 0 {
		return Directory{}, ErrFormat
	}
	endOffset := size - tailLen + int64(endIndex)
	end := tail[endIndex : endIndex+EndLen]
	if binary.LittleEndian.Uint16(end[4:6]) != 0 ||
		binary.LittleEndian.Uint16(end[6:8]) != 0 {
		return Directory{}, ErrFormat
	}
	recordsThisDisk := uint64(binary.LittleEndian.Uint16(end[8:10]))
	records := uint64(binary.LittleEndian.Uint16(end[10:12]))
	directorySize := uint64(binary.LittleEndian.Uint32(end[12:16]))
	directoryOffset := uint64(binary.LittleEndian.Uint32(end[16:20]))
	if recordsThisDisk != records {
		return Directory{}, ErrFormat
	}

	directoryEndOffset := endOffset
	if records == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff {
		var err error
		directoryEndOffset, records, directorySize, directoryOffset, err = readZip64(r, endOffset)
		if err != nil {
			return Directory{}, err
		}
	}
	if directorySize > maxDirBytes {
		return Directory{}, ErrScanLimit
	}
	directorySize64, sizeOK := toOffset(directorySize)
	directoryOffset64, offsetOK := toOffset(directoryOffset)
	if !sizeOK || !offsetOK || directoryEndOffset < 0 ||
		directorySize64 > directoryEndOffset || directoryOffset64 > directoryEndOffset {
		return Directory{}, ErrFormat
	}
	if records > directorySize/HeaderLen {
		return Directory{}, ErrFormat
	}

	return Directory{
		Offset:  directoryEndOffset - directorySize64,
		Size:    directorySize64,
		Records: records,
	}, nil
}

func findEnd(tail []byte) int {
	for i := len(tail) - EndLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:i+4]) != EndSignature {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20 : i+22]))
		if i+EndLen+commentLen == len(tail) {
			return i
		}
	}
	return -1
}

func readZip64(r io.ReaderAt, endOffset int64) (end int64, records, size, offset uint64, err error) {
	locatorOffset := endOffset - End64LocatorLen
	if locatorOffset < 0 {
		return 0, 0, 0, 0, ErrFormat
	}
	var locator [End64LocatorLen]byte
	if err := readAtFull(r, locator[:], locatorOffset); err != nil {
		return 0, 0, 0, 0, err
	}
	if binary.LittleEndian.Uint32(locator[0:4]) != End64LocatorSign ||
		binary.LittleEndian.Uint32(locator[4:8]) != 0 ||
		binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return 0, 0, 0, 0, ErrFormat
	}
	zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
	zip64Offset64, ok := toOffset(zip64Offset)
	if !ok || zip64Offset64 > locatorOffset {
		return 0, 0, 0, 0, ErrFormat
	}
	var record [End64Len]byte
	if err := readAtFull(r, record[:], zip64Offset64); err != nil {
		return 0, 0, 0, 0, err
	}
	if binary.LittleEndian.Uint32(record[0:4]) != End64Signature ||
		binary.LittleEndian.Uint64(record[4:12]) < End64Len-12 ||
		binary.LittleEndian.Uint32(record[16:20]) != 0 ||
		binary.LittleEndian.Uint32(record[20:24]) != 0 {
		return 0, 0, 0, 0, ErrFormat
	}
	recordsThisDisk := binary.LittleEndian.Uint64(record[24:32])
	records = binary.LittleEndian.Uint64(record[32:40])
	if recordsThisDisk != records {
		return 0, 0, 0, 0, ErrFormat
	}
	return zip64Offset64, records,
		binary.LittleEndian.Uint64(record[40:48]),
		binary.LittleEndian.Uint64(record[48:56]), nil
}

func toOffset(value uint64) (int64, bool) {
	if value > 1<<63-1 {
		return 0, false
	}
	return int64(value), true // #nosec G115 -- the MaxInt64 bound is checked above.
}

func readAtFull(r io.ReaderAt, dst []byte, offset int64) error {
	n, err := r.ReadAt(dst, offset)
	if n != len(dst) {
		if errors.Is(err, io.EOF) {
			return ErrFormat
		}
		if err != nil {
			return err
		}
		return ErrFormat
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
