package main

import (
	"encoding/binary"
	"testing"
)

func TestIDExpectedWraps(t *testing.T) {
	for _, tc := range []struct {
		id, base uint16
		count    int
		want     bool
	}{
		{0x9999, 0x9999, 3, true},
		{0x999b, 0x9999, 3, true},
		{0x999c, 0x9999, 3, false},
		{0xffff, 0xffff, 2, true},
		{0x0000, 0xffff, 2, true},
		{0x0001, 0xffff, 2, false},
		{0x1234, 0x9999, 65536, true},
	} {
		if got := idExpected(tc.id, tc.base, tc.count); got != tc.want {
			t.Fatalf("idExpected(%#04x, %#04x, %d) = %t, want %t", tc.id, tc.base, tc.count, got, tc.want)
		}
	}
}

func TestIPv4OfDoubleVLAN(t *testing.T) {
	frame := make([]byte, ethLen+2*vlanLen+ipLen)
	binary.BigEndian.PutUint16(frame[12:14], vlan8021AD)
	binary.BigEndian.PutUint16(frame[16:18], vlan8021Q)
	binary.BigEndian.PutUint16(frame[20:22], ethPIPv4)
	frame[22] = 0x45
	ip := ipv4Of(frame)
	if len(ip) != ipLen || ip[0] != 0x45 {
		t.Fatalf("ipv4Of() = %x", ip)
	}
}

func TestCarrierExpectedTCP(t *testing.T) {
	c := config{udpPort: 9, tcpPort: 443}
	ip := make([]byte, ipLen+20)
	ip[0] = 0x45
	ip[9] = ipProtoTCP
	binary.BigEndian.PutUint16(ip[ipLen+2:ipLen+4], 443)
	if !carrierExpected(ip, ipLen, 0, c) {
		t.Fatal("matching first TCP fragment was rejected")
	}
	binary.BigEndian.PutUint16(ip[ipLen+2:ipLen+4], 80)
	if carrierExpected(ip, ipLen, 0, c) {
		t.Fatal("wrong TCP destination port was accepted")
	}
	if !carrierExpected(ip[:ipLen], ipLen, 1, c) {
		t.Fatal("nonzero-offset TCP fragment was rejected")
	}
	ip[9] = 99
	if carrierExpected(ip, ipLen, 0, c) {
		t.Fatal("unexpected protocol was accepted")
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
