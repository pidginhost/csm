package webui

import (
	"os"
	"strings"
	"time"
)

// Sources of the host's time zone name. Tests replace them.
var (
	timeZoneEnv       = func() string { return os.Getenv("TZ") }
	readTimeZoneFile  = func() ([]byte, error) { return os.ReadFile("/etc/timezone") }
	readLocaltimeLink = func() (string, error) { return os.Readlink("/etc/localtime") }
)

// serverTimeZoneName returns the host's IANA time zone name, or "" when it
// cannot be determined. The browser needs the name to show "server time";
// Go only knows the loaded zone as "Local".
func serverTimeZoneName() string {
	valid := func(name string) string {
		name = strings.TrimSpace(name)
		if name == "" || name == "Local" {
			return ""
		}
		if _, err := time.LoadLocation(name); err != nil {
			return ""
		}
		return name
	}
	if name := valid(strings.TrimPrefix(timeZoneEnv(), ":")); name != "" {
		return name
	}
	if b, err := readTimeZoneFile(); err == nil {
		if name := valid(string(b)); name != "" {
			return name
		}
	}
	if target, err := readLocaltimeLink(); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			if name := valid(target[i+len("zoneinfo/"):]); name != "" {
				return name
			}
		}
	}
	return ""
}

// serverUTCOffsetMinutes is the fallback when the zone has no known name:
// the current offset, which is right until the next daylight-saving change.
func serverUTCOffsetMinutes() int {
	_, offset := time.Now().Zone()
	return offset / 60
}
