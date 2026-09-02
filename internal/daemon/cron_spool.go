package daemon

// cronSpoolWatchDir overrides the directory the realtime crontab watcher
// marks. Empty means "ask the platform". Tests redirect it under
// t.TempDir() without touching the real spool.
var cronSpoolWatchDir = "" //nolint:unused // Used by Linux watchers and cross-platform tests.
