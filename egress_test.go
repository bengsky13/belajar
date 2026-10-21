package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestEgressSolverAndFragments(t *testing.T) {
	src := net.ParseIP("192.0.2.2").To4()
	dst := net.ParseIP("198.51.100.7").To4()
	payload := bytesRepeat(4008, 0x11)
	for i := 0; i < 8; i++ {
		payload[i] = marker
	}
	if !egressSolve(payload, ipID, src, dst) {
		t.Fatal("solver found no adjustment")
	}
	whole := egressFragment(0, false, payload, ipID, src, dst)
	forwardTTL(whole)
	if got := csumFold(csumPartial(whole)); got != 0x004f {
		t.Fatalf("folded deferred checksum = %#04x, want 0x004f", got)
	}

	frag := egressFragment(8, true, payload[8:1480], ipID, src, dst)
	if got := binary.BigEndian.Uint16(frag[6:]); got != 0x2001 {
		t.Fatalf("fragment field = %#04x, want 0x2001", got)
	}
	if got := int(binary.BigEndian.Uint16(frag[2:])); got != len(frag) {
		t.Fatalf("total length = %d, want %d", got, len(frag))
	}
}

func TestEgressDoubleVLANFrame(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	ip := egressFragment(0, true, bytesRepeat(8, marker), ipID,
		net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"))
	frame := egressFrame(ip, srcMAC, dstMAC)
	if got := binary.BigEndian.Uint16(frame[12:]); got != vlanProto {
		t.Fatalf("outer ethertype = %#04x", got)
	}
	if got := binary.BigEndian.Uint16(frame[16:]); got != vlanProto {
		t.Fatalf("inner ethertype = %#04x", got)
	}
	if got := binary.BigEndian.Uint16(frame[20:]); got != ipProtoEth {
		t.Fatalf("payload ethertype = %#04x", got)
	}
	if frame[l2Len] != 0x45 {
		t.Fatalf("IPv4 starts at %d with %#02x", l2Len, frame[l2Len])
	}
}

func TestRouteEncoding(t *testing.T) {
	ip := net.ParseIP("172.17.0.1").To4()
	if got := routeIPv4(routeUint(ip)); !got.Equal(ip) {
		t.Fatalf("route round trip = %s, want %s", got, ip)
	}
}
