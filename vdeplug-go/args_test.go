package main

import "testing"

func TestParseArgsSeqpacketFD(t *testing.T) {
	if _, fd, _ := parseArgs([]string{"seqpacket://7"}); fd != 7 {
		t.Fatalf("fd = %d, want 7", fd)
	}
	if _, fd, _ := parseArgs([]string{"--descr", "g1", "seqpacket://12", "slirp://"}); fd != 12 {
		t.Fatalf("fd = %d, want 12", fd)
	}
}

// A missing or unparseable seqpacket fd must read as -1 so main rejects
// it — fd 0 would silently turn stdin into the link.
func TestParseArgsMissingOrGarbledFD(t *testing.T) {
	if _, fd, _ := parseArgs([]string{}); fd != -1 {
		t.Fatalf("no-argument fd = %d, want -1", fd)
	}
	if _, fd, _ := parseArgs([]string{"seqpacket://junk"}); fd != -1 {
		t.Fatalf("garbled fd = %d, want -1", fd)
	}
	if _, fd, _ := parseArgs([]string{"seqpacket://"}); fd != -1 {
		t.Fatalf("empty fd = %d, want -1", fd)
	}
}
