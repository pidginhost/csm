//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
)

const valiasesDir = "/etc/valiases"

// ForwarderWatcher watches /etc/valiases/ for changes using inotify.
type ForwarderWatcher struct {
	alertCh         chan<- alert.Finding
	knownForwarders []string
	inotifyFd       int
}

// NewForwarderWatcher creates a watcher for the valiases directory.
func NewForwarderWatcher(alertCh chan<- alert.Finding, knownForwarders []string) (*ForwarderWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}

	_, err = unix.InotifyAddWatch(fd, valiasesDir, unix.IN_CLOSE_WRITE)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inotify_add_watch(%s): %w", valiasesDir, err)
	}

	return &ForwarderWatcher{
		alertCh:         alertCh,
		knownForwarders: knownForwarders,
		inotifyFd:       fd,
	}, nil
}

// Run starts the watch loop. Blocks until stopCh is closed.
func (fw *ForwarderWatcher) Run(stopCh <-chan struct{}) {
	buf := make([]byte, 4096)

	// Use a polling approach since inotify fd + stopCh coordination
	// requires either epoll or periodic polling. Keep it simple.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			_ = unix.Close(fw.inotifyFd)
			return
		case <-ticker.C:
			fw.readEvents(buf)
		}
	}
}

func (fw *ForwarderWatcher) readEvents(buf []byte) {
	for {
		n, err := unix.Read(fw.inotifyFd, buf)
		if err != nil || n <= 0 {
			return // EAGAIN or error - no more events
		}

		offset := 0
		for offset < n {
			if offset+unix.SizeofInotifyEvent > n {
				break
			}
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(event.Len)
			if nameLen > 0 && offset+unix.SizeofInotifyEvent+nameLen <= n {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+nameLen]
				// Trim null bytes
				name := strings.TrimRight(string(nameBytes), "\x00")
				if name != "" && !strings.HasPrefix(name, ".") {
					fw.handleFileChange(name)
				}
			}
			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

func (fw *ForwarderWatcher) handleFileChange(domain string) {
	path := filepath.Join(valiasesDir, domain)

	// Load local domains for external detection
	localDomains := loadLocalDomainsForWatcher()

	findings := parseValiasFileForFindings(path, domain, localDomains, fw.knownForwarders)

	for _, f := range findings {
		f.Timestamp = time.Now()
		f.Details += "\n(detected in realtime via inotify)"
		select {
		case fw.alertCh <- f:
		default:
			fmt.Fprintf(os.Stderr, "[%s] Warning: alert channel full, dropping forwarder finding for %s\n",
				time.Now().Format("2006-01-02 15:04:05"), domain)
		}
	}
}

// loadLocalDomainsForWatcher reads local domain files. Separate from the checks
// package version to avoid import cycles.
func loadLocalDomainsForWatcher() map[string]bool {
	domains := make(map[string]bool)
	for _, path := range []string{"/etc/localdomains", "/etc/virtualdomains"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.IndexByte(line, ':'); idx > 0 {
				line = strings.TrimSpace(line[:idx])
			}
			domains[strings.ToLower(line)] = true
		}
	}
	return domains
}
