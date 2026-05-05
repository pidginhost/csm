//go:build ignore

// Package connection_bpfprog hosts the BPF C source for the cgroup/connect
// outbound-connection tracker and the generated Go bindings produced by
// bpf2go.
//
// To regenerate (needs clang + libbpf-devel; the CI builder image carries
// both):
//
//	make bpf-gen
package connection_bpfprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type conn_event Connection connection.bpf.c -- -I/usr/include
