package main

import (
	"strings"
	"testing"
)

func TestDoctor_FormatHumanIncludesSuggestions(t *testing.T) {
	d := DoctorReport{
		Checks: []DoctorCheck{
			{Name: "config valid", Status: "fail", Message: "missing infra_ips", Fix: "add infra_ips: [...] under csm.yaml"},
			{Name: "watchers attached", Status: "ok"},
		},
	}
	out := d.Human()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "Fix:") {
		t.Fatalf("expected FAIL and Fix: in human output, got %s", out)
	}
}

func TestDoctor_CollapseFails(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
		{Name: "c", Status: "fail"},
	}
	if got := collapseDoctor(checks); got != "fail" {
		t.Fatalf("expected fail, got %s", got)
	}
}

func TestDoctor_CollapseWarn(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "warn"},
	}
	if got := collapseDoctor(checks); got != "warn" {
		t.Fatalf("expected warn, got %s", got)
	}
}

func TestDoctor_CollapseOK(t *testing.T) {
	checks := []DoctorCheck{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "ok"},
	}
	if got := collapseDoctor(checks); got != "ok" {
		t.Fatalf("expected ok, got %s", got)
	}
}
