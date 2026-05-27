package processctx

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bootTimeCache caches the host boot time per proc root.
// Boot time is invariant for the life of a kernel; rereading /proc/stat
// on every Read() would only spend syscalls for an unchanging value.
type bootTimeCache struct {
	once sync.Once
	t    time.Time
	ok   bool
}

var procReaderBoot sync.Map // root -> *bootTimeCache

func (r *ProcReader) bootTime() (time.Time, bool) {
	v, _ := procReaderBoot.LoadOrStore(r.root, &bootTimeCache{})
	c := v.(*bootTimeCache)
	c.once.Do(func() {
		c.t, c.ok = readBootTime(filepath.Join(r.root, "stat"))
	})
	return c.t, c.ok
}

func readBootTime(statPath string) (time.Time, bool) {
	// #nosec G304 -- statPath is procReader.root + "stat"; root is operator-pinned.
	data, err := os.ReadFile(statPath)
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(sec, 0), true
		}
	}
	return time.Time{}, false
}

// clockTicksPerSecondOverride lets tests inject a known _SC_CLK_TCK
// without calling sysconf on the host.
var clockTicksPerSecondOverride int64

func clockTicksPerSecond() int64 {
	if clockTicksPerSecondOverride > 0 {
		return clockTicksPerSecondOverride
	}
	return defaultClockTicksPerSecond
}

// defaultClockTicksPerSecond is 100 on every mainstream Linux kernel
// CSM runs on (CONFIG_HZ_100=y). Reading sysconf would require cgo or
// a build-tagged platform shim; the constant is correct for every
// distribution kernel we target. Tests that want a different value
// set clockTicksPerSecondOverride.
const defaultClockTicksPerSecond = 100
