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
#include "csm_ringbuf.h"
static struct csm_queue_stats counts;
static uint64_t at_publication;
static void *bpf_map_lookup_elem(void *map, const void *key) { return &counts; }
static void *bpf_ringbuf_reserve(void *ring, uint64_t size, unsigned long flags) { return &counts; }
static void bpf_ringbuf_submit(void *event, unsigned long flags) {
    /* A consumer can run as soon as publication clears the busy bit. */
    at_publication = counts.submitted;
}
int main(void) {
    int event = 0;
    csm_ringbuf_submit(&event);
    printf("%llu\n", (unsigned long long)at_publication);
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
	published, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
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
