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
	if !egressSolve(payload, ipID, src, dst, ipProtoRaw, 0, 0x004f) {
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

func TestIPv4OfDoubleVLANFrame(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	want := egressFragment(0, true, bytesRepeat(8, marker), ipID,
		net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"))
	got := ipv4Of(egressFrame(want, srcMAC, dstMAC))
	if len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("decoded IPv4 packet differs: got %x want %x", got, want)
	}
}

func TestUDPCarrierGeometry(t *testing.T) {
	payload := bytesRepeat(4008, 0x11)
	egressUDPHeaders(payload, 0x0101, 9)
	if !egressSolve(payload, ipID, net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"), ipProtoUDP, 0, 0x004f) {
		t.Fatal("UDP carrier solver found no adjustment")
	}
	whole := egressFragment(0, false, payload, ipID,
		net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"), ipProtoUDP)
	forwardTTL(whole)
	if got := csumFold(csumPartial(whole)); got != 0x004f {
		t.Fatalf("UDP folded deferred checksum = %#04x, want 0x004f", got)
	}
	if got := binary.BigEndian.Uint16(payload[0:2]); got != 0x0101 {
		t.Fatalf("initial UDP source port = %#04x", got)
	}
	if got := binary.BigEndian.Uint16(payload[2:4]); got != 9 {
		t.Fatalf("initial UDP destination port = %d", got)
	}
	if got := binary.BigEndian.Uint16(payload[4:6]); got != uint16(len(payload)) {
		t.Fatalf("initial UDP length = %d, want %d", got, len(payload))
	}
	post := payload[mutatedIHL-ipLen:]
	if got := binary.BigEndian.Uint16(post[2:4]); got != 9 {
		t.Fatalf("post-mutation UDP destination port = %d", got)
	}
	if got := binary.BigEndian.Uint16(post[4:6]); got != uint16(len(post)) {
		t.Fatalf("post-mutation UDP length = %d, want %d", got, len(post))
	}
	if payload[0] != 1 || payload[1] != 1 || payload[2] != 0 {
		t.Fatalf("controlled options do not begin NOP,NOP,END: %x", payload[:3])
	}
}

func TestUDPCarrierMalformedTimestampOption(t *testing.T) {
	payload := bytesRepeat(4008, 0x11)
	egressUDPHeaders(payload, 0x4401, 53)
	if payload[0] != 0x44 || payload[1] != 0x01 {
		t.Fatalf("post-mutation option prefix = %x, want 4401", payload[:2])
	}
	if got := binary.BigEndian.Uint16(payload[2:4]); got != 53 {
		t.Fatalf("pre-mutation destination port = %d, want 53", got)
	}
}

func TestDeferredChecksumWordSolver(t *testing.T) {
	for _, desired := range []uint16{0x0000, 0x004f, 0x1234, 0x0001, 0xfffe} {
		payload := bytesRepeat(300, 0x5a)
		if !testo(payload, 0x2222, 0, desired) {
			t.Fatalf("solver found no adjustment for %#04x", desired)
		}
		pkt := datagram(0x2222, payload)
		forwardTTL(pkt)
		if got := csumFold(csumPartial(pkt)); got != desired {
			t.Fatalf("folded checksum = %#04x, want %#04x", got, desired)
		}
	}
	payload := bytesRepeat(300, 0x5a)
	if testo(payload, 0x2222, 0, 0xffff) {
		t.Fatal("solver unexpectedly produced the unattainable 0xffff checksum for a nonempty packet")
	}
}

func TestObservedIDAfterDeferredWrite(t *testing.T) {
	c := cfg{csumOffset: 4, csumWord: 0x1234}
	if got := observedID(c, 0x9999); got != 0x3412 {
		t.Fatalf("observed ID = %#04x, want 0x3412", got)
	}
}
