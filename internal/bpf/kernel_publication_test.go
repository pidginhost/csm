//go:build linux && bpf

package bpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKernelSubmissionCountPrecedesPublication(t *testing.T) {
	const source = `
#include <stdint.h>
#include <stdio.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
#define BPF_MAP_TYPE_ARRAY 2
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define SEC(section)
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
static void *bpf_map_lookup_elem(void *map, const void *key);
static void *bpf_ringbuf_reserve(void *ring, uint64_t size, unsigned long flags);
static void bpf_ringbuf_submit(void *event, unsigned long flags);
static long bpf_ringbuf_output(void *ring, void *data, uint64_t size, unsigned long flags);
#include "csm_ringbuf.h"
static struct csm_queue_stats counts;
static uint64_t at_publication;
static long output_err;
static void *bpf_map_lookup_elem(void *map, const void *key) { return &counts; }
static void *bpf_ringbuf_reserve(void *ring, uint64_t size, unsigned long flags) { return &counts; }
static void bpf_ringbuf_submit(void *event, unsigned long flags) {
    /* A consumer can run as soon as publication clears the busy bit. */
    at_publication = counts.submitted;
}
static long bpf_ringbuf_output(void *ring, void *data, uint64_t size, unsigned long flags) {
    if (output_err == 0) {
        at_publication = counts.submitted;
    }
    return output_err;
}
int main(void) {
    int event = 0;
    csm_ringbuf_submit(&event);
    unsigned long long submitted = at_publication;
    csm_ringbuf_output(&counts, &event, sizeof(event));
    unsigned long long output = at_publication;
    output_err = -11;
    long err = csm_ringbuf_output(&counts, &event, sizeof(event));
    printf("%llu %llu %ld %llu %llu\n", submitted, output, err,
           (unsigned long long)counts.submitted, (unsigned long long)counts.lost);
    return 0;
}
`
	dir := t.TempDir()
	code, binary := filepath.Join(dir, "publication.c"), filepath.Join(dir, "publication")
	if err := os.WriteFile(code, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cc", "-std=c11", "-O2", "-I../daemon/bpf_headers", code, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile counter helper with publication stub: %v\n%s", err, output)
	}
	output, err := exec.Command(binary).Output()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(output))
	// A copied record is counted before publication too, and a failed copy
	// leaves exactly one loss and no submission behind.
	if len(fields) != 5 || fields[1] != "2" || fields[2] != "-11" || fields[3] != "2" || fields[4] != "1" {
		t.Fatalf("output helper accounting = %q, want submit=1 output=2 err=-11 submitted=2 lost=1", output)
	}
	published, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	q := newKernelQueue(&measuredRing{}, func() (kernelCounts, error) { return kernelCounts{Submitted: published}, nil })
	if err := q.closeRing(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	finishKernelQueue(q, now, 1)
	got := kernelQueueSnapshot(q, now.Add(2*time.Minute), 1)
	if published != 1 || got.Status != "ok" || !got.DroppedLowerBound || got.DroppedTotal != 0 {
		t.Fatalf("consumption outran submission accounting: published=%d consumed=1 status=%+v", published, got)
	}
}
